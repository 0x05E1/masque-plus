package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"masque-plus/internal/logutil"
	"masque-plus/internal/netutil"

	"github.com/quic-go/quic-go"
)

// IP version selector
const (
	Any = iota
	V4
	V6
)

// TryCandidates iterates endpoints and returns the first that succeeds.
// maxToTry limits how many endpoints will be attempted (cap).
func TryCandidates(
	candidates []string,
	config netutil.MasqueConfig,
	maxToTry int,
	ping bool,
	pingTimeout time.Duration, // used by QUIC precheck
	perEndpointTimeout time.Duration, // informational; enforced by startFn
	url string,
) (string, error) {

	if maxToTry <= 0 || maxToTry > len(candidates) {
		maxToTry = len(candidates)
	}

	for i := 0; i < maxToTry; i++ {
		if i < maxToTry-1 {
			time.Sleep(1 * time.Second)
		}

		ep := candidates[i]
		logutil.Info("candidate", map[string]string{"endpoint": ep, "idx": fmt.Sprint(i + 1), "of": fmt.Sprint(maxToTry)})

		if ping {
			if !quicProbe(ep, pingTimeout) {
				logutil.Info("precheck failed (quic probe)", map[string]string{"endpoint": ep, "timeout": pingTimeout.String()})
				continue
			}
		}
		epaddr, err := netip.ParseAddrPort(ep)
		if err != nil {
			return "", err
		}
		config.Endpoint = &net.UDPAddr{
			IP:   net.IP(epaddr.Addr().AsSlice()),
			Port: int(epaddr.Port()),
		}
		err = netutil.TestConnection(config, url, perEndpointTimeout)
		if err != nil {
			logutil.Info("endpoint test failed", map[string]string{"endpoint": ep, "timeout": perEndpointTimeout.String()})
			continue
		}
		return ep, nil
	}

	return "", fmt.Errorf("no viable endpoint found (tried %d)", maxToTry)
}

// BuildCandidates expands IPv4/IPv6 CIDR ranges into a list of endpoints "host:port" (IPv6 as "[host]:port").
// BuildCandidates expands IPv4/IPv6 CIDR ranges into a list of endpoints "host:port" (IPv6 as "[host]:port").
// For each host, a port is chosen randomly from 'ports' if len(ports) > 1; otherwise the single port is used.
func BuildCandidates(ver int, v4CIDRs, v6CIDRs []string, ports []string) ([]string, error) {
	var out []string

	if len(ports) == 0 {
		ports = []string{"443"} // hard default
	}

	// IPv4
	if ver == Any || ver == V4 {
		for _, c := range v4CIDRs {
			ipnet, err := parseCIDR(c)
			if err != nil {
				logutil.Info("bad cidr", map[string]string{"cidr": c, "err": err.Error()})
				continue
			}
			if isIPv4Net(ipnet) {
				for ip := firstHost(ipnet); ip != nil && ipnet.Contains(ip); ip = nextIP(ip) {
					if isNetworkOrBroadcast(ip, ipnet) {
						continue
					}
					out = append(out, net.JoinHostPort(ip.String(), pickPort(ports)))
				}
			}
		}
	}

	// IPv6 (sample cap to avoid explosion)
	if ver == Any || ver == V6 {
		const v6Cap = 1024
		for _, c := range v6CIDRs {
			ipnet, err := parseCIDR(c)
			if err != nil {
				logutil.Info("bad cidr", map[string]string{"cidr": c, "err": err.Error()})
				continue
			}
			if !isIPv4Net(ipnet) {
				count := 0
				for ip := firstHost(ipnet); ip != nil && ipnet.Contains(ip) && count < v6Cap; ip = nextIP(ip) {
					out = append(out, fmt.Sprintf("[%s]:%s", ip.String(), pickPort(ports)))
					count++
				}
			}
		}
	}

	return out, nil
}

func pickPort(ports []string) string {
	if len(ports) == 1 {
		return ports[0]
	}
	return ports[rand.Intn(len(ports))]
}

// ---- QUIC precheck ----

// quicProbe does a quick QUIC (HTTP/3) handshake attempt against ep ("host:port" or "[v6]:port").
// Returns true if the handshake succeeds within timeout.
func quicProbe(ep string, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 1 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tconf := &tls.Config{
		InsecureSkipVerify: true,                             // probe only
		NextProtos:         []string{"h3", "h3-29", "h3-32"}, // common ALPNs
	}
	// set SNI only if host is a hostname (not an IP)
	if host, _, err := net.SplitHostPort(ep); err == nil {
		if net.ParseIP(trimBrackets(host)) == nil {
			tconf.ServerName = host
		}
	}

	qconf := &quic.Config{
		HandshakeIdleTimeout: timeout,
		MaxIdleTimeout:       timeout,
		KeepAlivePeriod:      0,
		// No datagrams/streams needed—just handshake
	}

	conn, err := quic.DialAddr(ctx, ep, tconf, qconf)
	if err != nil {
		return false
	}
	_ = conn.CloseWithError(0, "")
	return true
}

// ---- misc helpers ----

func trimBrackets(h string) string {
	h = strings.TrimPrefix(h, "[]")
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	return h
}

func parseCIDR(s string) (*net.IPNet, error) {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(s))
	return ipnet, err
}

func isIPv4Net(n *net.IPNet) bool {
	return n.IP.To4() != nil
}

func firstHost(n *net.IPNet) net.IP {
	ip := make(net.IP, len(n.IP))
	copy(ip, n.IP)
	return ip
}

func nextIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	b := ip.To16()
	if b == nil {
		return nil
	}
	out := make(net.IP, len(b))
	copy(out, b)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

func isNetworkOrBroadcast(ip net.IP, n *net.IPNet) bool {
	if ip == nil || n == nil || n.IP.To4() == nil {
		return false
	}
	mask := net.IP(n.Mask).To4()
	ip4 := ip.To4()
	network := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		network[i] = ip4[i] & mask[i]
	}
	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = network[i] | ^mask[i]
	}
	return ip4.Equal(network) || ip4.Equal(broadcast)
}

// ---- optional OS ping (kept for completeness; not used now) ----

func osPing(host string, timeout time.Duration) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		ms := int(timeout / time.Millisecond)
		cmd = exec.Command("ping", "-n", "1", "-w", fmt.Sprint(ms), host)
	} else {
		sec := int(timeout / time.Second)
		if sec == 0 {
			sec = 1
		}
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprint(sec), host)
	}
	return cmd.Run()
}
