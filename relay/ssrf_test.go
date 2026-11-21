package relay

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

// staticResolver maps host names to fixed answers, like a hostile DNS
// server would.
type staticResolver map[string][]string

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	ips, ok := r[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]netip.Addr, len(ips))
	for i, s := range ips {
		out[i] = netip.MustParseAddr(s)
	}
	return out, nil
}

func TestGuardAllowed(t *testing.T) {
	g := &Guard{}
	tests := map[string]bool{
		"8.8.8.8":                true,
		"1.1.1.1":                true,
		"2606:4700:4700::1111":   true,
		"127.0.0.1":              false,
		"127.10.0.1":             false,
		"10.1.2.3":               false,
		"172.16.0.1":             false,
		"172.31.255.255":         false,
		"172.32.0.1":             true,
		"192.168.1.1":            false,
		"169.254.169.254":        false, // AWS/GCP/Azure metadata
		"100.100.100.200":        false, // Alibaba metadata (CGNAT range)
		"100.64.0.1":             false,
		"0.0.0.0":                false,
		"255.255.255.255":        false,
		"224.0.0.1":              false,
		"198.18.0.1":             false,
		"::1":                    false,
		"::":                     false,
		"::ffff:127.0.0.1":       false, // IPv4-mapped loopback
		"::ffff:169.254.169.254": false,
		"::ffff:8.8.8.8":         true,
		"fe80::1":                false,
		"fd00:ec2::254":          false, // AWS IPv6 metadata
		"fc00::1":                false,
		"64:ff9b::a00:1":         false, // NAT64 of 10.0.0.1
		"2002:a00:1::":           false, // 6to4 of 10.0.0.1
		"ff02::1":                false,
	}
	for s, want := range tests {
		if got := g.Allowed(netip.MustParseAddr(s)); got != want {
			t.Errorf("Allowed(%s) = %v, want %v", s, got, want)
		}
	}
	if g.Allowed(netip.Addr{}) {
		t.Error("invalid address allowed")
	}
	allow := &Guard{Allow: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}}
	if !allow.Allowed(netip.MustParseAddr("10.20.1.1")) || allow.Allowed(netip.MustParseAddr("10.21.1.1")) {
		t.Error("allowlist not applied precisely")
	}
}

func TestGuardValidateURL(t *testing.T) {
	g := &Guard{}
	tests := []struct {
		url  string
		want error
	}{
		{"https://merchant.example/webhooks", nil},
		{"https://merchant.example:8443/w?x=1", nil},
		{"https://8.8.8.8/hook", nil},
		{"http://merchant.example/webhooks", ErrInvalid},
		{"ftp://merchant.example/", ErrInvalid},
		{"https://user:pass@merchant.example/", ErrInvalid},
		{"https:///nohost", ErrInvalid},
		{"://bad", ErrInvalid},
		{"https://127.0.0.1/admin", ErrBlockedDestination},
		{"https://[::1]/admin", ErrBlockedDestination},
		{"https://169.254.169.254/latest/meta-data/", ErrBlockedDestination},
		{"https://localhost/", ErrBlockedDestination},
		{"https://api.localhost/", ErrBlockedDestination},
	}
	for _, tt := range tests {
		if err := g.ValidateURL(tt.url); !errors.Is(err, tt.want) {
			t.Errorf("ValidateURL(%q) = %v, want %v", tt.url, err, tt.want)
		}
	}
	lenient := &Guard{AllowHTTP: true, Allow: loopback}
	for _, u := range []string{"http://localhost:8080/", "http://127.0.0.1:9/"} {
		if err := lenient.ValidateURL(u); err != nil {
			t.Errorf("lenient ValidateURL(%q) = %v", u, err)
		}
	}
}

func TestGuardDialUsesResolvedAddresses(t *testing.T) {
	srv := newScriptServer(t, always(http.StatusOK))
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	res := staticResolver{
		"rebind.example": {"127.0.0.1"},
		"meta.example":   {"169.254.169.254"},
		"mixed.example":  {"10.0.0.1", "127.0.0.1"},
	}
	strict := &Guard{Resolver: res}
	ctx := context.Background()
	for _, host := range []string{"rebind.example", "meta.example", "127.0.0.1"} {
		if _, err := strict.DialContext(ctx, "tcp", net.JoinHostPort(host, port)); !errors.Is(err, ErrBlockedDestination) {
			t.Errorf("dial %s: err = %v, want blocked", host, err)
		}
	}
	if _, err := strict.DialContext(ctx, "tcp", "nohost.example:443"); err == nil || errors.Is(err, ErrBlockedDestination) {
		t.Errorf("unresolvable host: err = %v", err)
	}
	if _, err := strict.DialContext(ctx, "tcp", "no-port"); err == nil {
		t.Error("address without port accepted")
	}

	// With loopback allowlisted, the guard skips the private answer and
	// connects to the allowed one.
	lenient := &Guard{Resolver: res, Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Dialer: &net.Dialer{Timeout: time.Second}}
	conn, err := lenient.DialContext(ctx, "tcp", net.JoinHostPort("mixed.example", port))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(conn.RemoteAddr().String(), "127.0.0.1:") {
		t.Fatalf("connected to %s", conn.RemoteAddr())
	}
	conn.Close()

	if err := strict.control("tcp", "127.0.0.1:80", nil); !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("control hook: %v", err)
	}
	if err := strict.control("tcp", "garbage", nil); !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("control hook garbage: %v", err)
	}
	if err := strict.control("tcp", "8.8.8.8:443", nil); err != nil {
		t.Errorf("control hook public: %v", err)
	}
}

// TestEngineRefusesInternalDestinations wires the guard into real
// deliveries: a hostname that resolves to loopback is dead-lettered with
// outcome "blocked" and the server never sees a request.
func TestEngineRefusesInternalDestinations(t *testing.T) {
	srv := newScriptServer(t, always(http.StatusOK))
	u, _ := url.Parse(srv.URL)
	res := staticResolver{"merchant.example": {"127.0.0.1"}}
	e := newTestEngine(t, Config{Guard: &Guard{Resolver: res, AllowHTTP: true}})
	ctx := context.Background()

	if _, err := e.CreateEndpoint(ctx, EndpointSpec{URL: srv.URL}); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("IP-literal loopback endpoint accepted: %v", err)
	}
	ep, err := e.CreateEndpoint(ctx, EndpointSpec{URL: "http://merchant.example:" + u.Port() + "/hook"})
	if err != nil {
		t.Fatal(err)
	}
	_, dlvs := publish(t, e, "pix.received", map[string]int{"amount": 1})
	waitFor(t, "dead letter", stateIs(e, dlvs[0].ID, StateDead))
	atts, _ := e.Attempts(ctx, dlvs[0].MessageID)
	if len(atts) != 1 || atts[0].Outcome != OutcomeBlocked || !strings.Contains(atts[0].Error, "not allowed") {
		t.Fatalf("attempts = %+v", atts)
	}
	if srv.count() != 0 {
		t.Fatal("blocked destination received a request")
	}
	if st, _ := e.BreakerState(ep.ID); st != BreakerClosed {
		t.Fatal("blocked attempts must not trip the breaker")
	}
}

// TestRedirects checks that redirects are not followed by default and that,
// when enabled, a redirect to an internal address is refused.
func TestRedirects(t *testing.T) {
	redir := newScriptServer(t, func(int, *http.Request) (int, http.Header, time.Duration) {
		return http.StatusFound, http.Header{"Location": {"http://169.254.169.254/latest/meta-data/"}}, 0
	})
	for _, follow := range []bool{false, true} {
		e := newTestEngine(t, Config{FollowRedirects: follow, Backoff: Schedule{}})
		if _, err := e.CreateEndpoint(context.Background(), EndpointSpec{URL: redir.URL}); err != nil {
			t.Fatal(err)
		}
		_, dlvs := publish(t, e, "charge.paid", nil)
		waitFor(t, "dead", stateIs(e, dlvs[0].ID, StateDead))
		atts, _ := e.Attempts(context.Background(), dlvs[0].MessageID)
		want := OutcomeRedirect
		if follow {
			want = OutcomeBlocked
		}
		if len(atts) != 1 || atts[0].Outcome != want {
			t.Fatalf("follow=%v: attempts = %+v", follow, atts)
		}
	}
}
