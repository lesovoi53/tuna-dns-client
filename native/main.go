// TUNA adapter for MIT-licensed MasterDnsVPN. The upstream wire protocol is unchanged.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"masterdnsvpn-go/internal/client"
	"masterdnsvpn-go/internal/config"
)

// selectPairs restricts the Cartesian product created by upstream bootstrap to
// explicitly selected domain/resolver pairs. Unknown selections fail closed.
func selectPairs(all []client.Connection, pairs map[string][]string) ([]*client.Connection, error) {
	known := make(map[string]map[string]int)
	for i, c := range all {
		if known[c.Domain] == nil {
			known[c.Domain] = make(map[string]int)
		}
		known[c.Domain][c.ResolverLabel] = i
	}
	selected := make(map[int]bool)
	for domain, endpoints := range pairs {
		if len(endpoints) == 0 || known[domain] == nil {
			return nil, errors.New("invalid pair selection")
		}
		for _, endpoint := range endpoints {
			i, ok := known[domain][endpoint]
			if !ok {
				return nil, errors.New("unknown pair selection")
			}
			selected[i] = true
		}
	}
	if len(selected) == 0 {
		return nil, errors.New("empty pair selection")
	}
	result := make([]*client.Connection, 0, len(selected))
	for i := range all {
		if selected[i] {
			result = append(result, &all[i])
		}
	}
	return result, nil
}

func applyPairFile(app *client.Client, path string) error {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > 2*1024*1024 {
		return errors.New("pair selection too large")
	}
	var pairs map[string][]string
	decoder := json.NewDecoder(f)
	if err := decoder.Decode(&pairs); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("trailing pair selection")
	} else if err != io.EOF {
		return err
	}
	selected, err := selectPairs(app.Balancer().AllConnections(), pairs)
	if err != nil {
		return err
	}
	app.Balancer().SetConnections(selected)
	return nil
}

// A complete scan with no compatible resolvers is a normal negative result.
// Upstream may return nil after cancellation, so context failure takes priority.
func compatibilityScan(ctx context.Context, app *client.Client) error {
	if app.Balancer().TotalCount() == 0 {
		return client.ErrNoValidConnections
	}
	err := app.RunInitialMTUTests(ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, client.ErrNoValidConnections) {
		return nil
	}
	return err
}

func main() {
	path := flag.String("config", "", "Private TOML configuration path")
	resolvers := flag.String("resolvers", "", "Private resolver file path")
	pairs := flag.String("pairs", "", "Optional private JSON file mapping domains to normalized resolver endpoints")
	scan := flag.Bool("scan", false, "Run native resolver and MTU compatibility checks only")
	scanWorkers := flag.Int("scan-workers", 32, "Concurrent native scan probes (1..128)")
	validate := flag.Bool("validate", false, "Validate configuration and pair selections without networking")
	flag.Parse()
	fail := func(message string) {
		fmt.Println("TUNA_MASTER_ERROR " + message)
		if *scan {
			fmt.Println("TUNA_SCAN_FAILED")
		}
		os.Exit(1)
	}
	if *path == "" || *resolvers == "" || flag.NArg() != 0 {
		fail("required private input missing")
	}
	cfg, err := config.LoadClientConfigWithOverrides(*path, config.ClientConfigOverrides{ResolversFilePath: resolvers})
	if err != nil {
		fail("configuration rejected")
	}
	if *scan {
		if *scanWorkers < 1 || *scanWorkers > 128 {
			fail("scan workers must be between 1 and 128")
		}
		cfg.MTUTestParallelism = *scanWorkers
		// Upstream adaptive parallelism raises small requested limits. The
		// isolated build overlay honors this explicit scan-only limit instead.
		client.TUNAScanWorkers = *scanWorkers
	}
	app, err := client.BootstrapLoadedConfig(cfg, "")
	if err != nil {
		fail("bootstrap failed")
	}
	if err := applyPairFile(app, *pairs); err != nil {
		fail("pair selection rejected")
	}
	if *validate {
		fmt.Println("TUNA_MASTER_VALID")
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *scan {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		err = compatibilityScan(ctx, app)
		// RunInitialMTUTests joins all probe workers before these snapshots.
		for _, c := range app.Balancer().AllConnections() {
			b, _ := json.Marshal(map[string]any{"resolver": c.ResolverLabel, "domain": c.Domain, "valid": c.IsValid, "upload": c.UploadMTUBytes, "download": c.DownloadMTUBytes})
			fmt.Println("TUNA_RESOLVER " + string(b))
		}
		if err != nil || ctx.Err() != nil {
			fmt.Println("TUNA_SCAN_FAILED")
			os.Exit(2)
		}
		fmt.Println("TUNA_SCAN_DONE")
		return
	}
	if err := app.Run(ctx); err != nil {
		fail("runtime failed")
	}
}
