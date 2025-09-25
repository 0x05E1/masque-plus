package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Copied from https://github.com/Diniboy1123/usque/blob/7a934d8b60a38f883bf780f9d9ccd13a70b52442/internal/dns.go

type TunnelDNSResolver struct {
	TunNet   *netstack.Net
	DNSAddrs []netip.Addr
	Timeout  time.Duration
}

func (r TunnelDNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if len(r.DNSAddrs) == 0 {
		return ctx, nil, fmt.Errorf("no DNS servers configured")
	}

	var queryCtx context.Context = ctx
	var cancel context.CancelFunc
	if r.Timeout > 0 {
		queryCtx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}

	type result struct {
		ip  net.IP
		err error
	}
	results := make(chan result, len(r.DNSAddrs))

	for _, dnsAddr := range r.DNSAddrs {
		dnsHost := net.JoinHostPort(dnsAddr.String(), "53")

		go func(dnsHost string) {
			var dialFunc func(context.Context, string, string) (net.Conn, error)
			if r.TunNet != nil {
				dialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
					return r.TunNet.DialContext(ctx, "udp", dnsHost)
				}
			} else {
				dialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
					return net.Dial("udp", dnsHost)
				}
			}

			resolver := &net.Resolver{
				PreferGo: true,
				Dial:     dialFunc,
			}
			ips, err := resolver.LookupIP(queryCtx, "ip", name)
			if err == nil && len(ips) > 0 {
				results <- result{ip: ips[0], err: nil}
			} else {
				results <- result{ip: nil, err: err}
			}
		}(dnsHost)
	}

	var lastErr error
	for i := 0; i < len(r.DNSAddrs); i++ {
		res := <-results
		if res.err == nil && res.ip != nil {
			if cancel != nil {
				cancel()
			}
			return ctx, res.ip, nil
		}
		lastErr = res.err
	}

	return ctx, nil, fmt.Errorf("all DNS servers failed: %v", lastErr)
}
