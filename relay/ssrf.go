package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
)

// Resolver resolves host names. *net.Resolver satisfies it; tests inject
// fakes to simulate DNS that points at internal addresses.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// blockedPrefixes are destinations a webhook must never reach unless
// explicitly allowlisted: loopback, RFC 1918 and unique-local private
// ranges, link-local (which includes the 169.254.169.254 cloud metadata
// service), carrier-grade NAT (which includes 100.100.100.200, another
// metadata address), and assorted special-purpose ranges.
var blockedPrefixes = mustPrefixes(
	"0.0.0.0/8",       // "this network"
	"10.0.0.0/8",      // RFC 1918
	"100.64.0.0/10",   // carrier-grade NAT
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local, cloud metadata
	"172.16.0.0/12",   // RFC 1918
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"192.88.99.0/24",  // 6to4 relay anycast
	"192.168.0.0/16",  // RFC 1918
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, broadcast
	"::/128",          // unspecified
	"::1/128",         // loopback
	"64:ff9b::/96",    // NAT64 (could embed any IPv4)
	"64:ff9b:1::/48",  // local-use NAT64
	"100::/64",        // discard-only
	"2001::/32",       // Teredo
	"2001:db8::/32",   // documentation
	"2002::/16",       // 6to4 (embeds IPv4)
	"fc00::/7",        // unique local (includes fd00:ec2::254 metadata)
	"fe80::/10",       // link-local
	"ff00::/8",        // multicast
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// Guard enforces the destination policy for outgoing deliveries.
//
// The check runs on the IP addresses a connection is actually made to:
// Guard resolves the host itself, filters the results, and dials only an
// allowed address, so a hostname that resolves to 10.0.0.5 (or that
// re-resolves to it between validation and use, "DNS rebinding") is refused.
// A net.Dialer Control hook re-checks the connected socket address as a
// second line of defense. Because every connection goes through the guard,
// redirects, when enabled, are checked as well.
type Guard struct {
	// Allow lists prefixes that are reachable even though they are in a
	// blocked range (for example a VPC range for internal consumers, or
	// 127.0.0.0/8 in tests).
	Allow []netip.Prefix
	// Resolver defaults to net.DefaultResolver.
	Resolver Resolver
	// Dialer is used for the final connection. Its Control hook is replaced.
	Dialer *net.Dialer
	// AllowHTTP permits plain-http endpoint URLs. Default: https only.
	AllowHTTP bool
}

// Allowed reports whether ip may be connected to.
func (g *Guard) Allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return false
	}
	for _, p := range g.Allow {
		if p.Contains(ip) {
			return true
		}
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// ValidateURL checks an endpoint URL when it is registered: scheme, absence
// of credentials, and, for IP-literal hosts, the address policy. Hostnames
// are checked again at connection time, after DNS.
func (g *Guard) ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: url: %v", ErrInvalid, err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !g.AllowHTTP {
			return fmt.Errorf("%w: url must use https", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: url scheme must be https", ErrInvalid)
	}
	if u.User != nil {
		return fmt.Errorf("%w: url must not contain credentials", ErrInvalid)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: url has no host", ErrInvalid)
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		if !g.Allowed(netip.MustParseAddr("127.0.0.1")) {
			return fmt.Errorf("%w: %s", ErrBlockedDestination, host)
		}
	}
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && !g.Allowed(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedDestination, ip)
	}
	return nil
}

// DialContext resolves addr, drops disallowed addresses and connects to the
// first allowed one that answers. Use it as http.Transport.DialContext.
func (g *Guard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		r := g.Resolver
		if r == nil {
			r = net.DefaultResolver
		}
		ips, err = r.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	var allowed []netip.Addr
	for _, ip := range ips {
		if g.Allowed(ip) {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("%w: %s resolves to %v", ErrBlockedDestination, host, ips)
	}
	d := net.Dialer{}
	if g.Dialer != nil {
		d = *g.Dialer
	}
	d.Control = g.control
	var lastErr error
	for _, ip := range allowed {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// control re-checks the address the socket is about to connect to.
func (g *Guard) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparseable address %q", ErrBlockedDestination, address)
	}
	if !g.Allowed(ap.Addr()) {
		return fmt.Errorf("%w: %s", ErrBlockedDestination, ap.Addr())
	}
	return nil
}

// isBlocked reports whether err came from the guard.
func isBlocked(err error) bool { return errors.Is(err, ErrBlockedDestination) }
