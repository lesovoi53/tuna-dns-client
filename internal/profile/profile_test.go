package profile

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func sample() Profile {
	return Profile{Name: "Sample", Domains: []string{"dns.example.com", "dns2.example.com"}, Key: "test-only-key", Encryption: 5, Resolvers: []string{"1.1.1.1", "[2606:4700:4700::1111]:53"}, Tuning: map[string]any{"resolver_balancing_strategy": 5, "upload_compression_type": 2, "base_encode_data": true, "ping_aggressive_interval_seconds": 0.05}}
}
func storm(t *testing.T, modify func(map[string]any)) string {
	t.Helper()
	p := map[string]any{"name": "Example", "domains": []string{"DNS.Example.COM.", "dns2.example.com"}, "server": map[string]any{"domain": "dns.example.com", "encryption_key": "test-only-key", "encryption_method": 5}, "resolvers": "1.1.1.1\n8.8.8.8:5353", "resolver_balancing_strategy": 5, "rx_tx_workers": 16, "tunnel_process_workers": 0, "base_encode_data": true, "ping_aggressive_interval_seconds": 0.05}
	if modify != nil {
		modify(p)
	}
	b, err := json.Marshal(map[string]any{"schema": "whitedns.profile", "version": 1, "profile": p})
	if err != nil {
		t.Fatal(err)
	}
	return "stormdns://" + base64.StdEncoding.EncodeToString(b)
}
func tuna(t *testing.T, raw []byte) string {
	t.Helper()
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	if _, e := w.Write(raw); e != nil {
		t.Fatal(e)
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return "tuna://" + base64.RawURLEncoding.EncodeToString(b.Bytes())
}
func TestParseServerFormats(t *testing.T) {
	s := storm(t, nil)
	doc, _ := json.Marshal(map[string]any{"name": "Outer name", "uri": s})
	for _, link := range []string{s, tuna(t, doc)} {
		p, err := Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Domains) != 2 || p.Domains[0] != "dns.example.com" || p.Key != "test-only-key" || p.Encryption != 5 || p.Resolvers[1] != "8.8.8.8:5353" {
			t.Fatal("profile content mismatch")
		}
		if p.Tuning["resolver_balancing_strategy"] != json.Number("5") {
			t.Fatalf("lost strategy: %v", p.Tuning)
		}
		if strings.HasPrefix(link, "tuna://") && p.Name != "Outer name" {
			t.Fatal("wrapper name lost")
		}
	}
}
func TestParseRejectsInvalidAndBounded(t *testing.T) {
	links := []string{"https://example.com", "tuna://not-valid", "stormdns://no", "tuna://" + strings.Repeat("A", 128*1024+1), tuna(t, bytes.Repeat([]byte("x"), maxEnvelopeBytes+1)), storm(t, func(p map[string]any) { p["resolvers"] = "secret.invalid" }), storm(t, func(p map[string]any) { p["domains"] = []string{} }), storm(t, func(p map[string]any) { p["resolver_balancing_strategy"] = 9 }), storm(t, func(p map[string]any) { p["base_encode_data"] = "true" })}
	for i, link := range links {
		if _, e := Parse(link); e == nil {
			t.Errorf("accepted malformed link %d", i)
		} else if strings.Contains(e.Error(), "secret.invalid") {
			t.Fatal("untrusted value leaked in error")
		}
	}
}
func TestResolverSelection(t *testing.T) {
	p := sample()
	p.Selected = map[string][]string{"dns.example.com": nil}
	if len(p.ResolversFor("dns.example.com")) != 2 {
		t.Fatal("nil must inherit")
	}
	p.Selected["dns.example.com"] = []string{}
	if len(p.ResolversFor("dns.example.com")) != 0 || p.Validate() == nil {
		t.Fatal("empty selection must fail closed")
	}
	p.Selected["dns.example.com"] = []string{"9.9.9.9"}
	if p.Validate() != nil || p.ResolversFor("dns.example.com")[0] != "9.9.9.9" || len(p.ResolversFor("dns2.example.com")) != 2 {
		t.Fatal("domain selections interfere")
	}
	copy := p.ResolversFor("dns.example.com")
	copy[0] = "bad"
	if p.Selected["dns.example.com"][0] != "9.9.9.9" {
		t.Fatal("selection aliased")
	}
}
func TestNumericResolvers(t *testing.T) {
	for _, s := range []string{"1.1.1.1", "8.8.8.8:5353", "2001:db8::1", "[2001:db8::1]", "[2001:db8::1]:65535"} {
		if _, e := ResolverAddress(s); e != nil {
			t.Errorf("valid %q: %v", s, e)
		}
	}
	for _, s := range []string{"dns.google", "1.1.1.1:0", "1.1.1.1:65536", "[fe80::1%eth0]:53", "1.1.1.1\n8.8.8.8", "[1.1.1.1]"} {
		if _, e := ResolverAddress(s); e == nil {
			t.Errorf("accepted %q", s)
		}
	}
	n, e := NormalizeResolvers([]string{"1.1.1.1", "1.1.1.1:53", "::ffff:1.1.1.1"})
	if e != nil || len(n) != 1 || n[0] != "1.1.1.1:53" {
		t.Fatal("canonical deduplication failed")
	}
}
func TestManagedTOML(t *testing.T) {
	p := sample()
	p.Key = "key\"\nline\t\\\x01"
	p.Tuning["log_level"] = "DEBUG"
	s, e := TOML(p, 10808, []string{p.Domains[1]})
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"DOMAINS = [\"dns2.example.com\"]", "LISTEN_IP = \"127.0.0.1\"", "LISTEN_PORT = 10808", "LOCAL_DNS_ENABLED = false", "SOCKS5_AUTH = false", "LOG_LEVEL = \"WARN\"", "RESOLVER_BALANCING_STRATEGY = 5", "PING_AGGRESSIVE_INTERVAL_SECONDS = 0.05", "\\u0001"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(s, "RESOLVERS =") || strings.Contains(s, "DEBUG") || strings.Contains(s, "\\x01") {
		t.Fatal("unsafe or unsupported TOML")
	}
	if _, e = TOML(p, 10808, []string{"other.example.com"}); e == nil {
		t.Fatal("accepted foreign domain")
	}
	p.Tuning["listen_ip"] = "0.0.0.0"
	if _, e = TOML(p, 10808, nil); e == nil {
		t.Fatal("accepted unmanaged option")
	}
}
func TestValidateTuning(t *testing.T) {
	for _, bad := range []map[string]any{{"arq_window_size": 1.1}, {"mtu_test_timeout": math.NaN()}, {"mtu_test_timeout": math.Inf(1)}, {"upload_compression_type": 4}, {"base_encode_data": 1}, {"mtu_servers_file_name": "../escape"}, {"min_upload_mtu": 200}, {"resolver_balancing_strategy": 5, "RESOLVER_BALANCING_STRATEGY": 5}} {
		p := sample()
		p.Tuning = bad
		if p.Validate() == nil {
			t.Errorf("accepted invalid tuning %v", bad)
		}
	}
}
func TestExports(t *testing.T) {
	for _, kind := range []string{"sing-box", "xray"} {
		for _, full := range []bool{false, true} {
			for _, port := range []int{10808, 10809} {
				text, e := Export(kind, full, port)
				if e != nil {
					t.Fatal(e)
				}
				var doc map[string]any
				if e = json.Unmarshal([]byte(text), &doc); e != nil {
					t.Fatal(e)
				}
				if strings.Contains(text, "test-only-key") || strings.Contains(text, "direct") {
					t.Fatal("export leaked key or direct bypass")
				}
				if full {
					in := doc["inbounds"].([]any)[0].(map[string]any)
					var inbound float64
					if kind == "xray" {
						inbound = in["port"].(float64)
					} else {
						inbound = in["listen_port"].(float64)
					}
					if int(inbound) == port || in["listen"] != "127.0.0.1" {
						t.Fatal("inbound collision or public listener")
					}
				}
			}
		}
	}
	if _, e := Export("unsupported", true, 10808); e == nil {
		t.Fatal("unknown format accepted")
	}
}

func TestTUNARejectsTrailingAndTruncatedCompression(t *testing.T) {
	doc, _ := json.Marshal(map[string]any{"uri": storm(t, nil)})
	good := tuna(t, doc)
	compressed, _ := decode64(strings.TrimPrefix(good, "tuna://"))
	for _, bad := range [][]byte{append(append([]byte{}, compressed...), 0), compressed[:len(compressed)-2]} {
		if _, err := Parse("tuna://" + base64.RawURLEncoding.EncodeToString(bad)); err == nil {
			t.Fatal("accepted invalid compressed stream")
		}
	}
}
