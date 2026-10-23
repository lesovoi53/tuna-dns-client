// Package profile imports server links and creates managed native/proxy configurations.
package profile

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxStormBytes = 65536
const maxEnvelopeBytes = 4 * 1024 * 1024

// Profile contains one server and independent resolver selections for its domains.
type Profile struct {
	Name       string              `json:"name"`
	Domains    []string            `json:"domains"`
	Key        string              `json:"key"`
	Encryption int                 `json:"encryption"`
	Resolvers  []string            `json:"resolvers"`
	Selected   map[string][]string `json:"selected"`
	Tuning     map[string]any      `json:"tuning"`
}

// Parse supports stormdns and the compressed TUNA envelope containing its URI.
func Parse(link string) (Profile, error) {
	if len(link) > 128*1024+32 {
		return Profile{}, errors.New("profile link too large")
	}
	link = strings.TrimSpace(link)
	name := ""
	if strings.HasPrefix(strings.ToLower(link), "tuna://") {
		encoded := link[len("tuna://"):]
		if len(encoded) > 128*1024 {
			return Profile{}, errors.New("profile link too large")
		}
		compressed, err := decode64(encoded)
		if err != nil {
			return Profile{}, errors.New("invalid TUNA encoding")
		}
		compressedInput := bytes.NewReader(compressed)
		reader, err := zlib.NewReader(compressedInput)
		if err != nil {
			return Profile{}, errors.New("invalid TUNA compression")
		}
		raw, err := io.ReadAll(io.LimitReader(reader, maxEnvelopeBytes+1))
		closeErr := reader.Close()
		if err != nil || closeErr != nil || compressedInput.Len() != 0 || len(raw) > maxEnvelopeBytes {
			return Profile{}, errors.New("invalid or oversized TUNA document")
		}
		var wrapper struct {
			Name string `json:"name"`
			URI  string `json:"uri"`
		}
		if err = decodeJSON(raw, &wrapper); err != nil {
			return Profile{}, errors.New("invalid TUNA document")
		}
		link = strings.TrimSpace(wrapper.URI)
		name = wrapper.Name
	}
	if !strings.HasPrefix(strings.ToLower(link), "stormdns://") || len(link) > 100000 {
		return Profile{}, errors.New("expected a stormdns or TUNA DNS profile")
	}
	raw, err := decode64(link[len("stormdns://"):])
	if err != nil || len(raw) > maxStormBytes {
		return Profile{}, errors.New("invalid or oversized DNS profile")
	}
	var root struct {
		Schema  string                     `json:"schema"`
		Version int                        `json:"version"`
		Profile map[string]json.RawMessage `json:"profile"`
	}
	if decodeJSON(raw, &root) != nil || root.Schema != "whitedns.profile" || root.Version != 1 || root.Profile == nil {
		return Profile{}, errors.New("unsupported DNS profile document")
	}
	fields := root.Profile
	var server struct {
		Domain     string `json:"domain"`
		Key        string `json:"encryption_key"`
		Encryption *int   `json:"encryption_method"`
	}
	if json.Unmarshal(fields["server"], &server) != nil || server.Encryption == nil {
		return Profile{}, errors.New("invalid DNS server settings")
	}
	p := Profile{Name: "MasterDnsVPN", Key: server.Key, Encryption: *server.Encryption, Tuning: map[string]any{}, Selected: map[string][]string{}}
	if v, ok := fields["name"]; ok && json.Unmarshal(v, &p.Name) != nil {
		return Profile{}, errors.New("invalid profile name")
	}
	if name != "" {
		p.Name = name
	}
	if v, ok := fields["domains"]; ok {
		if json.Unmarshal(v, &p.Domains) != nil {
			return Profile{}, errors.New("invalid domains")
		}
	} else {
		p.Domains = []string{server.Domain}
	}
	for i, d := range p.Domains {
		p.Domains[i] = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	}
	var resolverText string
	if json.Unmarshal(fields["resolvers"], &resolverText) != nil {
		return Profile{}, errors.New("invalid resolver list")
	}
	for _, r := range strings.Split(strings.ReplaceAll(resolverText, "\r", ""), "\n") {
		if r = strings.TrimSpace(r); r != "" {
			p.Resolvers = append(p.Resolvers, r)
		}
	}
	for key, value := range fields {
		canonical := strings.ToUpper(key)
		if _, ok := tuningTypes[canonical]; !ok {
			continue
		}
		if _, exists := p.Tuning[strings.ToLower(canonical)]; exists {
			return Profile{}, errors.New("duplicate tuning setting")
		}
		var v any
		if decodeJSON(value, &v) != nil {
			return Profile{}, errors.New("invalid tuning setting")
		}
		p.Tuning[strings.ToLower(canonical)] = v
	}
	if err = p.Validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}

func decode64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, e := enc.Strict().DecodeString(s); e == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64")
}
func decodeJSON(raw []byte, target any) error {
	if !utf8.Valid(raw) {
		return errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(target); err != nil {
		return errors.New("invalid JSON")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func validDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// ResolverAddress validates a numeric DNS endpoint and returns its canonical identity.
func ResolverAddress(value string) (netip.AddrPort, error) {
	fail := errors.New("resolver must be a numeric IP with optional port 1-65535")
	if len(value) > 128 || value != strings.TrimSpace(value) || strings.Contains(value, "%") {
		return netip.AddrPort{}, fail
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return netip.AddrPortFrom(addr.Unmap(), 53), nil
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		if addr, err := netip.ParseAddr(value[1 : len(value)-1]); err == nil && addr.Is6() {
			return netip.AddrPortFrom(addr.Unmap(), 53), nil
		}
	}
	ap, err := netip.ParseAddrPort(value)
	if err != nil || ap.Port() == 0 {
		return netip.AddrPort{}, fail
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}
func validResolvers(values []string) error {
	if len(values) < 1 || len(values) > 128 {
		return errors.New("provide 1 to 128 DNS resolvers")
	}
	seen := map[netip.AddrPort]bool{}
	for _, v := range values {
		ap, err := ResolverAddress(v)
		if err != nil {
			return err
		}
		if seen[ap] {
			return errors.New("duplicate DNS resolver")
		}
		seen[ap] = true
	}
	return nil
}

// ResolversFor inherits defaults only for missing or nil selections. An explicit
// empty slice stays empty and is rejected by Validate; it never falls back.
func (p Profile) ResolversFor(domain string) []string {
	if selected, ok := p.Selected[domain]; ok && selected != nil {
		return append([]string{}, selected...)
	}
	return append([]string(nil), p.Resolvers...)
}
func (p Profile) Validate() error {
	if !utf8.ValidString(p.Name) || len(p.Name) > 512 || strings.ContainsAny(p.Name, "\x00\r\n") {
		return errors.New("invalid profile name")
	}
	if len(p.Domains) < 1 || len(p.Domains) > 16 {
		return errors.New("provide 1 to 16 tunnel domains")
	}
	domains := map[string]bool{}
	exactDomains := map[string]bool{}
	for _, d := range p.Domains {
		id := strings.ToLower(d)
		if !validDomain(d) || domains[id] {
			return errors.New("invalid or duplicate tunnel domain")
		}
		domains[id] = true
		exactDomains[d] = true
	}
	if strings.TrimSpace(p.Key) == "" || len(p.Key) > 4096 || !utf8.ValidString(p.Key) || strings.ContainsRune(p.Key, 0) || p.Encryption < 0 || p.Encryption > 5 {
		return errors.New("invalid encryption key or method")
	}
	if err := validResolvers(p.Resolvers); err != nil {
		return err
	}
	for d, values := range p.Selected {
		if !exactDomains[d] {
			return errors.New("resolver selection references an unknown domain")
		}
		if values != nil {
			if err := validResolvers(values); err != nil {
				return err
			}
		}
	}
	_, err := validatedTuning(p.Tuning)
	return err
}

func numeric(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, e := n.Float64()
		return f, e == nil
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	}
	return 0, false
}
func validatedTuning(tuning map[string]any) (map[string]any, error) {
	out := map[string]any{}
	for key, v := range tuning {
		key = strings.ToUpper(key)
		kind, ok := tuningTypes[key]
		if !ok {
			return nil, errors.New("unsupported native tuning setting")
		}
		if _, exists := out[key]; exists {
			return nil, errors.New("duplicate tuning setting")
		}
		invalid := false
		switch kind {
		case "bool":
			_, ok = v.(bool)
			invalid = !ok
		case "string":
			s, ok := v.(string)
			invalid = !ok || len(s) > 2048 || !utf8.ValidString(s) || strings.ContainsRune(s, 0)
			if key == "MTU_SERVERS_FILE_NAME" {
				invalid = invalid || s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\:")
			}
		default:
			n, ok := numeric(v)
			invalid = !ok || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 1e9
			if kind == "int" {
				invalid = invalid || math.Trunc(n) != n
			}
			switch key {
			case "RESOLVER_BALANCING_STRATEGY":
				invalid = invalid || n > 8
			case "UPLOAD_COMPRESSION_TYPE", "DOWNLOAD_COMPRESSION_TYPE":
				invalid = invalid || n > 3
			}
			if kind == "int" {
				v = int64(n)
			} else {
				v = n
			}
		}
		if invalid {
			return nil, errors.New("invalid native tuning value")
		}
		out[key] = v
	}
	for _, pair := range [][2]string{{"MIN_UPLOAD_MTU", "MAX_UPLOAD_MTU"}, {"MIN_DOWNLOAD_MTU", "MAX_DOWNLOAD_MTU"}} {
		low := tuningDefaults[pair[0]]
		high := tuningDefaults[pair[1]]
		if v, ok := out[pair[0]]; ok {
			low, _ = numeric(v)
		}
		if v, ok := out[pair[1]]; ok {
			high, _ = numeric(v)
		}
		if low > high {
			return nil, errors.New("minimum MTU exceeds maximum")
		}
	}
	return out, nil
}

// TOML creates a managed native SOCKS configuration. Resolvers belong in the
// separate resolver file passed to the core, never in this document.
func TOML(p Profile, port int, domains []string) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	if port < 1 || port > 65535 {
		return "", errors.New("invalid SOCKS port")
	}
	if domains == nil {
		domains = p.Domains
	}
	if len(domains) == 0 {
		return "", errors.New("no active domains")
	}
	allowed := map[string]bool{}
	for _, d := range p.Domains {
		allowed[d] = true
	}
	seen := map[string]bool{}
	for _, d := range domains {
		if !allowed[d] || seen[d] {
			return "", errors.New("invalid active domains")
		}
		seen[d] = true
	}
	values, _ := validatedTuning(p.Tuning)
	values["DOMAINS"] = domains
	values["DATA_ENCRYPTION_METHOD"] = p.Encryption
	values["ENCRYPTION_KEY"] = p.Key
	values["PROTOCOL_TYPE"] = "SOCKS5"
	values["LISTEN_IP"] = "127.0.0.1"
	values["LISTEN_PORT"] = port
	values["SOCKS5_AUTH"] = false
	values["LOCAL_DNS_ENABLED"] = false
	values["LOG_LEVEL"] = "WARN"
	// Imported file names must never cause writes outside the private runtime directory.
	values["SAVE_MTU_SERVERS_TO_FILE"] = false
	values["LOCAL_DNS_CACHE_PERSIST_TO_FILE"] = false
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		encoded, err := tomlValue(values[k])
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%s = %s\n", k, encoded)
	}
	return b.String(), nil
}
func tomlValue(v any) (string, error) {
	// JSON string escaping is compatible with TOML basic strings (unlike Go's \x escapes).
	switch x := v.(type) {
	case string:
		b, _ := json.Marshal(x)
		return string(b), nil
	case []string:
		items := make([]string, len(x))
		for i, s := range x {
			items[i], _ = tomlValue(s)
		}
		return "[" + strings.Join(items, ", ") + "]", nil
	case bool:
		return strconv.FormatBool(x), nil
	default:
		n, ok := numeric(v)
		if !ok {
			return "", errors.New("unsupported configuration value")
		}
		return strconv.FormatFloat(n, 'f', -1, 64), nil
	}
}

// Export creates a SOCKS outbound or minimal complete sing-box/Xray config.
// The local DNS tunnel client must remain running; this is not a native DNS transport.
func Export(kind string, full bool, port int) (string, error) {
	if port < 1 || port > 65535 {
		return "", errors.New("invalid SOCKS port")
	}
	inboundPort := 10809
	if inboundPort == port {
		inboundPort++
	}
	var outbound map[string]any
	var result any
	switch strings.ToLower(kind) {
	case "singbox", "sing-box":
		outbound = map[string]any{"type": "socks", "tag": "tuna-dns", "server": "127.0.0.1", "server_port": port, "version": "5"}
		result = outbound
		if full {
			result = map[string]any{"log": map[string]any{"level": "warn"}, "inbounds": []any{map[string]any{"type": "mixed", "tag": "local-in", "listen": "127.0.0.1", "listen_port": inboundPort}}, "outbounds": []any{outbound}, "route": map[string]any{"final": "tuna-dns"}}
		}
	case "xray":
		outbound = map[string]any{"protocol": "socks", "tag": "tuna-dns", "settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": port}}}}
		result = outbound
		if full {
			result = map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"tag": "local-in", "listen": "127.0.0.1", "port": inboundPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{outbound}}
		}
	default:
		return "", errors.New("export kind must be sing-box or Xray")
	}
	b, err := json.MarshalIndent(result, "", "  ")
	return string(b) + "\n", err
}

// NormalizeResolvers validates and canonicalizes scanner candidates, removing
// equivalent endpoints. Unlike a profile selection, a candidate list may exceed 128.
func NormalizeResolvers(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := map[netip.AddrPort]bool{}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		ap, err := ResolverAddress(v)
		if err != nil {
			return nil, err
		}
		if !seen[ap] {
			result = append(result, ap.String())
			seen[ap] = true
		}
	}
	return result, nil
}
