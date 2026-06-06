package models

import (
	"net"
	"os"
	"testing"
)

// fakeResolver is a deterministic, fully offline dnsResolver used by the models
// test suite. Forward and reverse lookups are served from static maps; any host
// or address that is not present returns a not-found error, so the
// "unresolvable host" branches of BuildSBAccess are exercised exactly as they
// would be against real DNS — but without ever touching the network.
type fakeResolver struct {
	forward map[string][]net.IP // hostname -> IP addresses
	reverse map[string][]string // IP string -> names (PTR records)
}

// LookupIP returns the configured addresses for host, or a not-found DNSError.
func (f fakeResolver) LookupIP(host string) ([]net.IP, error) {
	if ips, ok := f.forward[host]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// LookupAddr returns the configured names for addr, or a not-found DNSError.
func (f fakeResolver) LookupAddr(addr string) ([]string, error) {
	if names, ok := f.reverse[addr]; ok {
		return names, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

// newTestResolver returns the fake resolver wired with every hostname and
// address the models tests depend on. The values are chosen to match the
// assertions in access_test.go, user_test.go and group_test.go:
//   - localhost resolves to 127.0.0.1 (single address, so the prefix is stable);
//   - test.com / one.one.one.one resolve to fixed addresses so AddAccess and
//     HasAccess round-trips are deterministic;
//   - reverse lookups of the loopback addresses yield "localhost".
//
// Trailing dots on the PTR names mimic real resolver output (BuildSBAccess trims
// them).
func newTestResolver() fakeResolver {
	return fakeResolver{
		forward: map[string][]net.IP{
			"localhost":       {net.ParseIP("127.0.0.1")},
			"test.com":        {net.ParseIP("93.184.216.34")},
			"meow.com":        {net.ParseIP("203.0.113.10")},
			"one.one.one.one": {net.ParseIP("1.1.1.1")},
		},
		reverse: map[string][]string{
			"127.0.0.1": {"localhost."},
			"::1":       {"localhost."},
		},
	}
}

// TestMain installs the deterministic resolver for the entire package so every
// test that reaches BuildSBAccess (directly or via AddAccess) is hermetic. It
// restores the production resolver afterwards for good hygiene, even though the
// process exits immediately.
func TestMain(m *testing.M) {
	prev := accessResolver
	accessResolver = newTestResolver()
	code := m.Run()
	accessResolver = prev
	os.Exit(code)
}
