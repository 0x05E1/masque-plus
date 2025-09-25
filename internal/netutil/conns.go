package netutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"masque-plus/internal/cryptoutil"
	"masque-plus/internal/dns"
	"masque-plus/internal/httpcheck"
	"masque-plus/internal/logutil"
	"net"
	"net/netip"
	"os"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/api"
	"github.com/quic-go/quic-go"
	"github.com/things-go/go-socks5"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const ConnectURI = "https://cloudflareaccess.com"

type MasqueConfig struct {
	LocalAddresses    []netip.Addr
	Endpoint          *net.UDPAddr
	PrivKey           *ecdsa.PrivateKey
	PeerPubKey        *ecdsa.PublicKey
	UseIpv6           bool
	SNI               string
	DnsAddrs          []netip.Addr
	MTU               int
	InitialPacketSize uint16
	KeepalivePeriod   time.Duration
	ReconnectDelay    time.Duration
	DnsTimeout        time.Duration
	LocalDns          bool
}

type SocksConfig struct {
	MasqueConfig
	BindIP   string
	BindPort string
}

func TestConnection(config MasqueConfig, url string, timeout time.Duration) error {
	cert, err := cryptoutil.GenerateCert(config.PrivKey, config.PeerPubKey)
	if err != nil {
		return err
	}

	tlsConfig, err := api.PrepareTlsConfig(config.PrivKey, config.PeerPubKey, cert, config.SNI)
	if err != nil {
		return err
	}

	tunDev, tunNet, err := netstack.CreateNetTUN(config.LocalAddresses, config.DnsAddrs, config.MTU)
	if err != nil {
		return err
	}
	defer tunDev.Close()

	go oneTimeTunnel(context.Background(), tlsConfig, config.KeepalivePeriod, config.InitialPacketSize, config.Endpoint, api.NewNetstackAdapter(tunDev), config.MTU)

	checkResult, err := httpcheck.CheckWarpOverDialer(tunNet, url, nil, timeout)
	if err != nil {
		return err
	}
	if checkResult != httpcheck.StatusOK {
		return fmt.Errorf("%v", checkResult)
	}
	return nil
}

func RunMasqueSocks(config SocksConfig, connectTimeout time.Duration) error {
	// TODO: use connectTimeout
	cert, err := cryptoutil.GenerateCert(config.PrivKey, config.PeerPubKey)
	if err != nil {
		return err
	}

	tlsConfig, err := api.PrepareTlsConfig(config.PrivKey, config.PeerPubKey, cert, config.SNI)
	if err != nil {
		return err
	}

	tunDev, tunNet, err := netstack.CreateNetTUN(config.LocalAddresses, config.DnsAddrs, config.MTU)
	if err != nil {
		return err
	}
	defer tunDev.Close()

	go api.MaintainTunnel(context.Background(), tlsConfig, config.KeepalivePeriod, config.InitialPacketSize, config.Endpoint, api.NewNetstackAdapter(tunDev), config.MTU, config.ReconnectDelay)

	var resolver socks5.NameResolver
	if config.LocalDns {
		resolver = dns.TunnelDNSResolver{TunNet: nil, DNSAddrs: config.DnsAddrs, Timeout: config.DnsTimeout}
	} else {
		resolver = dns.TunnelDNSResolver{TunNet: tunNet, DNSAddrs: config.DnsAddrs, Timeout: config.DnsTimeout}
	}

	var server = socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tunNet.DialContext(ctx, network, addr)
		}),
		socks5.WithResolver(resolver),
	)
	return server.ListenAndServe("tcp", net.JoinHostPort(config.BindIP, config.BindPort))
}

// Copied directly from https://github.com/Diniboy1123/usque/blob/7a934d8b60a38f883bf780f9d9ccd13a70b52442/api/tunnel.go#L160-L256
// with changes to disable reconnecting. ideally this should be PR'd into usque
func oneTimeTunnel(ctx context.Context, tlsConfig *tls.Config, keepalivePeriod time.Duration, initialPacketSize uint16, endpoint *net.UDPAddr, device api.TunnelDevice, mtu int) {
	packetBufferPool := api.NewNetBuffer(mtu)
	logutil.Info(fmt.Sprintf("Establishing MASQUE connection to %s:%d", endpoint.IP, endpoint.Port), nil)
	udpConn, tr, ipConn, rsp, err := api.ConnectTunnel(
		ctx,
		tlsConfig,
		&quic.Config{
			EnableDatagrams:   true,
			KeepAlivePeriod:   keepalivePeriod,
			InitialPacketSize: initialPacketSize,
		},
		ConnectURI,
		endpoint,
	)
	if err != nil {
		logutil.Error(fmt.Sprintf("Connection test error: Failed to connect tunnel: %s", err), nil)
		return
	}
	if ipConn != nil {
		defer ipConn.Close()
	}
	if udpConn != nil {
		defer udpConn.Close()
	}
	if tr != nil {
		defer tr.Close()
	}
	if rsp.StatusCode != 200 {
		logutil.Error(fmt.Sprintf("Connection test error: Tunnel connection failed: %s", rsp.Status), nil)
		return
	}

	logutil.Info("Connection test: Connected to MASQUE server", nil)
	errChan := make(chan error, 2)

	go func() {
		for {
			buf := packetBufferPool.Get()
			n, err := device.ReadPacket(buf)
			if err != nil {
				packetBufferPool.Put(buf)
				errChan <- fmt.Errorf("failed to read from TUN device: %v", err)
				return
			}
			icmp, err := ipConn.WritePacket(buf[:n])
			if err != nil {
				packetBufferPool.Put(buf)
				if errors.As(err, new(*connectip.CloseError)) {
					errChan <- fmt.Errorf("connection closed while writing to IP connection: %v", err)
					return
				}
				logutil.Error(fmt.Sprintf("Error writing to IP connection: %v, continuing...", err), nil)
				continue
			}
			packetBufferPool.Put(buf)

			if len(icmp) > 0 {
				if err := device.WritePacket(icmp); err != nil {
					if errors.As(err, new(*connectip.CloseError)) {
						errChan <- fmt.Errorf("connection closed while writing ICMP to TUN device: %v", err)
						return
					}
					logutil.Error(fmt.Sprintf("Error writing ICMP to TUN device: %v, continuing...", err), nil)
					continue
				}
			}
		}
	}()

	go func() {
		buf := packetBufferPool.Get()
		defer packetBufferPool.Put(buf)
		for {
			n, err := ipConn.ReadPacket(buf, true)
			if err != nil {
				if errors.As(err, new(*connectip.CloseError)) {
					errChan <- fmt.Errorf("connection closed while reading from IP connection: %v", err)
					return
				}
				logutil.Error(fmt.Sprintf("Error reading from IP connection: %v, continuing...", err), nil)
				continue
			}
			if err := device.WritePacket(buf[:n]); err != nil {
				errChan <- fmt.Errorf("failed to write to TUN device: %v", err)
				return
			}
		}
	}()

	err = <-errChan
	logutil.Error(fmt.Sprintf("Connection test error: Tunnel disconnected: %s", err), nil)
}
