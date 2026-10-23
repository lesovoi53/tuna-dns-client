//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"tuna-dns-client/internal/profile"
)

func integrationProfile() profile.Profile {
	return profile.Profile{Name: "Integration fixture", Domains: []string{"one.example.com", "two.example.com"}, Key: "test-only-secret-never-log", Encryption: 5, Resolvers: []string{"1.1.1.1:53", "8.8.8.8:53"}, Selected: map[string][]string{"one.example.com": {"1.1.1.1:53"}, "two.example.com": {"8.8.8.8:53"}}, Tuning: map[string]any{"resolver_balancing_strategy": 5, "upload_compression_type": 2, "download_compression_type": 2}}
}
func TestDPAPIRoundTripAndTamper(t *testing.T) {
	plaintext := []byte("test-only-protected-secret")
	ciphertext, err := crypt(plaintext, true)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}
	restored, err := crypt(ciphertext, false)
	if err != nil || !bytes.Equal(restored, plaintext) {
		t.Fatalf("DPAPI round trip failed: %v", err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xff
	if _, err = crypt(ciphertext, false); err == nil {
		t.Fatal("tampered DPAPI data accepted")
	}
}

func TestConnectionStagesAndSafeLogs(t *testing.T) {
	a := &App{State: State{Logs: []string{}, Status: "connecting"}}
	for _, s := range []string{"TUNA_MASTER_CONNECTING", "TUNA_STAGE_MTU", "TUNA_SCAN_PROGRESS 1 2", "TUNA_SCAN_PROGRESS 2 2", "TUNA_STAGE_SESSION", "TUNA_STAGE_SESSION_RETRY", "TUNA_STAGE_SESSION", "TUNA_STAGE_SESSION_OK"} {
		a.runtimeEvent(s)
	}
	if a.Status != "connecting" || a.Connection.Attempt != 2 || a.Connection.Done != 2 || a.Connection.Total != 2 {
		t.Fatalf("bad state %+v", a.Connection)
	}
	a.runtimeEvent("TUNA_MASTER_READY")
	if a.Status != "connected" {
		t.Fatal("ready not connected")
	}
	a.runtimeEvent("TUNA_STAGE_RESET")
	if a.Status != "connecting" {
		t.Fatal("reset not connecting")
	}
	a.runtimeEvent("ENCRYPTION_KEY=do-not-expose-this-secret")
	a.runtimeEvent("TUNA_MASTER_ERROR do-not-expose-this-secret")
	if strings.Contains(strings.Join(a.Logs, "\n"), "do-not-expose-this-secret") {
		t.Fatal("raw native secret exposed")
	}
	a.runtimeEvent("TUNA_STAGE_MTU")
	if a.Connection.Done != 0 || a.Connection.Total != 0 {
		t.Fatal("new MTU pass retained stale progress")
	}
}

func TestScanWorkerBoundsAndProgress(t *testing.T) {
	core, err := filepath.Abs("assets/core.exe")
	if err != nil {
		t.Fatal(err)
	}
	a, err := newApp(context.Background(), t.TempDir(), core)
	if err != nil {
		t.Fatal(err)
	}
	p := integrationProfile()
	p.Tuning["mtu_test_retries"] = 1
	p.Tuning["mtu_test_timeout"] = 0.1
	a.Profiles = []profile.Profile{p}
	for _, n := range []int{-1, 0, 129} {
		if err = a.scan(p.Domains[0], []string{"127.0.0.1:9"}, n); err == nil {
			t.Fatalf("accepted workers %d", n)
		}
	}
	if err = a.scan(p.Domains[0], []string{"127.0.0.1:9", "127.0.0.1:19"}, 1); err != nil {
		t.Fatal(err)
	}
	defer a.stop(true)
	deadline := time.Now().Add(15 * time.Second)
	previous := 0
	for {
		s := a.snapshot()
		if s.Scan.Total != 2 || s.Scan.Workers != 1 || s.Scan.Done < previous || s.Scan.Done > 2 {
			t.Fatalf("bad scan progress: %+v", s.Scan)
		}
		previous = s.Scan.Done
		if !s.Scan.Running {
			if s.Scan.Error != "" || s.Scan.Done != 2 || len(s.Scan.Results) != 2 {
				t.Fatalf("incomplete negative scan: %+v", s.Scan)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scan timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
	reloaded, err := newApp(context.Background(), a.dir, core)
	if err != nil || reloaded.ScanWorkers != 1 {
		t.Fatalf("workers not persisted: %v", err)
	}
}
func TestEncryptedPersistenceAndPerDomainReload(t *testing.T) {
	dir := t.TempDir()
	a, err := newApp(context.Background(), dir, "not-started.exe")
	if err != nil {
		t.Fatal(err)
	}
	p := integrationProfile()
	a.Profiles = []profile.Profile{p}
	a.Port = 12080
	if err = a.persist(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "profiles.dpapi"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{p.Key, p.Name, p.Domains[0], "resolver_balancing_strategy"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("profile persisted as plaintext")
		}
	}
	loaded, err := newApp(context.Background(), dir, "not-started.exe")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Port != 12080 || len(loaded.Profiles) != 1 || loaded.Profiles[0].Key != p.Key || !reflect.DeepEqual(loaded.Profiles[0].Selected, p.Selected) {
		t.Fatal("saved profile or independent selections changed")
	}
	if _, err = loaded.action(context.Background(), Request{Action: "resetResolvers", Domain: p.Domains[0]}); err != nil {
		t.Fatal(err)
	}
	again, err := newApp(context.Background(), dir, "not-started.exe")
	if err != nil {
		t.Fatal(err)
	}
	got := again.Profiles[0]
	if len(got.ResolversFor(p.Domains[0])) != 2 || !reflect.DeepEqual(got.ResolversFor(p.Domains[1]), p.Selected[p.Domains[1]]) {
		t.Fatal("reset affected another domain or failed to restore default")
	}
}
func TestRuntimeFilesAcceptedByPinnedNativeCore(t *testing.T) {
	core, err := filepath.Abs(filepath.Join("assets", "core.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(core); err != nil {
		t.Fatal("packaged core missing:", err)
	}
	a, err := newApp(context.Background(), t.TempDir(), core)
	if err != nil {
		t.Fatal(err)
	}
	p := integrationProfile()
	dir, err := a.runtimeFiles(p, p.Domains, p.Selected, 10808)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(configuration), "RESOLVER_BALANCING_STRATEGY = 5") {
		t.Fatal("strategy 5 not preserved")
	}
	pairBytes, err := os.ReadFile(filepath.Join(dir, "pairs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pairs map[string][]string
	if json.Unmarshal(pairBytes, &pairs) != nil || !reflect.DeepEqual(pairs, p.Selected) {
		t.Fatal("per-domain pairs changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, core, "-config", filepath.Join(dir, "config.toml"), "-resolvers", filepath.Join(dir, "resolvers.txt"), "-pairs", filepath.Join(dir, "pairs.json"), "-validate")
	hide(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("native offline validation failed: %v, %s", err, out)
	}
	if !bytes.Contains(out, []byte("TUNA_MASTER_VALID")) {
		t.Fatalf("missing native success marker: %s", out)
	}
	if bytes.Contains(out, []byte(p.Key)) {
		t.Fatal("native output leaked key")
	}
}

// fakeSOCKS handles one local test connection and records the destination sent
// over the wire. It never performs external DNS resolution or networking.
func fakeSOCKS(t *testing.T, reply []byte, after func(net.Conn)) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	destination := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		greeting := make([]byte, 3)
		if _, err = io.ReadFull(conn, greeting); err != nil {
			return
		}
		if !bytes.Equal(greeting, []byte{5, 1, 0}) {
			return
		}
		if _, err = conn.Write([]byte{5, 0}); err != nil {
			return
		}
		header := make([]byte, 5)
		if _, err = io.ReadFull(conn, header); err != nil {
			return
		}
		if !bytes.Equal(header[:4], []byte{5, 1, 0, 3}) {
			return
		}
		payload := make([]byte, int(header[4])+2)
		if _, err = io.ReadFull(conn, payload); err != nil {
			return
		}
		destination <- net.JoinHostPort(string(payload[:len(payload)-2]), strconv.Itoa(int(binary.BigEndian.Uint16(payload[len(payload)-2:]))))
		if _, err = conn.Write(reply); err != nil {
			return
		}
		if after != nil {
			after(conn)
		}
	}()
	return ln.Addr().String(), destination
}
func readDestination(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKS request not received")
		return ""
	}
}

var socksSuccess = []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}

func TestSOCKSUsesRemoteHostname(t *testing.T) {
	proxy, requests := fakeSOCKS(t, socksSuccess, func(c net.Conn) { c.Write([]byte("tunnel-data")) })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := socksDial(proxy)(ctx, "tcp", "unresolvable.test.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := readDestination(t, requests); got != "unresolvable.test.invalid:443" {
		t.Fatalf("destination changed: %s", got)
	}
	b, err := io.ReadAll(conn)
	if err != nil || string(b) != "tunnel-data" {
		t.Fatalf("SOCKS stream failed: %v", err)
	}
}
func TestSOCKSRejectsMalformedReply(t *testing.T) {
	for _, reply := range [][]byte{{4, 0, 0, 1, 127, 0, 0, 1, 0, 0}, {5, 0, 1, 1, 127, 0, 0, 1, 0, 0}, {5, 0, 0, 99}, {5, 0, 0, 4, 1, 2}} {
		proxy, _ := fakeSOCKS(t, reply, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err := socksDial(proxy)(ctx, "tcp", "unresolvable.test.invalid:443")
		cancel()
		if conn != nil {
			conn.Close()
		}
		if err == nil {
			t.Fatalf("malformed reply accepted: %v", reply)
		}
	}
}
func TestSOCKSFailureDoesNotFallBackToDirect(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	proxy, _ := fakeSOCKS(t, []byte{5, 5, 0, 1, 127, 0, 0, 1, 0, 0}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := socksDial(proxy)(ctx, "tcp", target.Addr().String())
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("rejected SOCKS connection succeeded")
	}
	target.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
	conn, err = target.Accept()
	if conn != nil {
		conn.Close()
		t.Fatal("direct fallback contacted target")
	}
	if err == nil {
		t.Fatal("unexpected direct target result")
	}
}
func TestProbeValidatesTLSCertificateThroughSOCKS(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "unexpectedly accepted") }))
	defer tlsServer.Close()
	proxy, requests := fakeSOCKS(t, socksSuccess, func(client net.Conn) {
		upstream, err := net.Dial("tcp", tlsServer.Listener.Addr().String())
		if err != nil {
			return
		}
		defer upstream.Close()
		done := make(chan struct{})
		go func() { io.Copy(upstream, client); close(done) }()
		io.Copy(client, upstream)
		<-done
	})
	_, portText, _ := net.SplitHostPort(proxy)
	port, _ := strconv.Atoi(portText)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if _, err := probe(ctx, port); err == nil {
		t.Fatal("untrusted or mismatched TLS certificate accepted")
	}
	if got := readDestination(t, requests); got != "www.cloudflare.com:443" {
		t.Fatalf("HTTPS destination not delegated to SOCKS: %s", got)
	}
}
func TestStartRejectsOccupiedLocalPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	a, err := newApp(context.Background(), t.TempDir(), "must-not-launch.exe")
	if err != nil {
		t.Fatal(err)
	}
	a.Profiles = []profile.Profile{integrationProfile()}
	a.Port = ln.Addr().(*net.TCPAddr).Port
	if err = a.start(); err == nil || !strings.Contains(err.Error(), "порт занят") {
		t.Fatalf("occupied port not rejected before launching: %v", err)
	}
	if a.cancel != nil || a.Status != "disconnected" {
		t.Fatal("failed start changed process lifecycle")
	}
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("failed start left runtime secrets")
	}
}
