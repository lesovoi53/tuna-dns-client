package main

import (
	"context"
	"errors"
	"io"
	"masterdnsvpn-go/internal/client"
	"masterdnsvpn-go/internal/config"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompatibilityScanDistinguishesNegativeFromInterrupted(t *testing.T) {
	// A local UDP socket which never replies cannot produce tunnel compatibility.
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	dir := t.TempDir()
	conf := filepath.Join(dir, "config.toml")
	resolvers := filepath.Join(dir, "resolvers.txt")
	if err := os.WriteFile(conf, []byte("DOMAINS = [\"a.example\", \"b.example\", \"c.example\"]\nENCRYPTION_KEY = \"test-key\"\nMTU_TEST_RETRIES = 1\nMTU_TEST_TIMEOUT = 0.01\nLOG_LEVEL = \"ERROR\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolvers, []byte(socket.LocalAddr().String()), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadClientConfigWithOverrides(conf, config.ClientConfigOverrides{ResolversFilePath: &resolvers})
	if err != nil {
		t.Fatal(err)
	}
	app, err := client.BootstrapLoadedConfig(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client.TUNAScanWorkers = 2
	defer func() { client.TUNAScanWorkers = 0 }()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previousStdout := os.Stdout
	os.Stdout = writer
	scanErr := compatibilityScan(ctx, app)
	os.Stdout = previousStdout
	writer.Close()
	progress, readErr := io.ReadAll(reader)
	reader.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	var markers []string
	for _, line := range strings.Split(string(progress), "\n") {
		if strings.HasPrefix(line, "TUNA_SCAN_PROGRESS ") {
			markers = append(markers, line)
		}
	}
	if strings.Join(markers, "\n") != "TUNA_SCAN_PROGRESS 1 3\nTUNA_SCAN_PROGRESS 2 3\nTUNA_SCAN_PROGRESS 3 3" {
		t.Fatalf("expected one monotonic completion per actual probe; got %q", markers)
	}
	if scanErr != nil {
		t.Fatalf("complete negative scan should succeed: %v", scanErr)
	}
	for _, c := range app.Balancer().AllConnections() {
		if c.IsValid {
			t.Fatal("silent socket classified as compatible")
		}
	}
	interrupted, stop := context.WithCancel(context.Background())
	stop()
	if err := compatibilityScan(interrupted, app); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan must fail even though upstream returns nil: %v", err)
	}
	app.Balancer().SetConnections(nil)
	if err := compatibilityScan(context.Background(), app); err == nil {
		t.Fatal("empty scan should fail closed")
	}
}

func TestSelectPairsDoesNotCreateCrossDomainSelections(t *testing.T) {
	all := []client.Connection{
		{Domain: "a.example", ResolverLabel: "1.1.1.1:53", Key: "a1"},
		{Domain: "a.example", ResolverLabel: "8.8.8.8:53", Key: "a8"},
		{Domain: "b.example", ResolverLabel: "1.1.1.1:53", Key: "b1"},
		{Domain: "b.example", ResolverLabel: "8.8.8.8:53", Key: "b8"},
	}
	got, err := selectPairs(all, map[string][]string{"a.example": {"1.1.1.1:53"}, "b.example": {"8.8.8.8:53"}})
	if err != nil || len(got) != 2 || got[0].Key != "a1" || got[1].Key != "b8" {
		t.Fatalf("unexpected selected connections: %v, %v", got, err)
	}
	for _, pairs := range []map[string][]string{nil, {}, {"a.example": {}}, {"unknown.example": {"1.1.1.1:53"}}, {"a.example": {"9.9.9.9:53"}}, {"a.example": {"1.1.1.1:53", "unknown"}}} {
		if _, err := selectPairs(all, pairs); err == nil {
			t.Fatalf("accepted invalid selection: %v", pairs)
		}
	}
}
