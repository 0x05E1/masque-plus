package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"masque-plus/internal/cryptoutil"
	"masque-plus/internal/logutil"
	"masque-plus/internal/netutil"
	"masque-plus/internal/scanner"

	"github.com/Diniboy1123/usque/api"
	usqueConfig "github.com/Diniboy1123/usque/config"
)

var (
	defaultV4 = []string{
		"162.159.198.1:443",
		"162.159.198.2:443",
	}
	defaultV6 = []string{
		"2606:4700:103::1",
		"2606:4700:103::2",
	}
	defaultRange4 = []string{
		"162.159.192.0/24",
		"162.159.197.0/24",
		"162.159.198.0/24",
	}
	defaultRange6 = []string{
		"2606:4700:102::/48",
	}
	defaultBind           = "127.0.0.1:1080"
	defaultConfigFile     = "./config.json"
	defaultConnectTimeout = 15 * time.Minute
	defaultTestURL        = "https://connectivity.cloudflareclient.com/cdn-cgi/trace"
	defaultSNI            = "consumer-masque.cloudflareclient.com"
	defaultDnsStr         = "1.1.1.1,8.8.8.8"

	defaultModel  = "PC"
	defaultLocale = "en_US"
)

var (
	connectPort       = 443
	dnsStr            string
	dnsTimeout        = 2 * time.Second
	initialPacketSize = 1242
	keepalivePeriod   = 30 * time.Second
	localDns          bool
	mtu               = 1280
	noTunnelIpv4      bool
	noTunnelIpv6      bool
	reconnectDelay    = 1 * time.Second
	sni               = defaultSNI
	useIpv6           bool
	Version           = "dev"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		logutil.Msg("INFO", fmt.Sprintf("Masque-Plus Version: %s", Version), nil)
		logutil.Msg("INFO", fmt.Sprintf("Environment: %s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH), nil)
		os.Exit(0)
	}
	endpointStr := flag.String("endpoint", "", "Endpoint to connect (IPv4, IPv6, domain; host or host:Port; for IPv6 with port use [IPv6]:Port)")
	bind := flag.String("bind", defaultBind, "IP:Port to bind SOCKS proxy")
	renew := flag.Bool("renew", false, "Force renewal of config even if config.json exists")
	scan := flag.Bool("scan", false, "Scan/auto-select a default endpoint")
	v4Flag := flag.Bool("4", false, "Force IPv4 endpoint list with --scan")
	v6Flag := flag.Bool("6", false, "Force IPv6 endpoint list with --scan")
	connectTimeout := flag.Duration("connect-timeout", defaultConnectTimeout, "Overall timeout for the final connect/process to be up")
	range4 := flag.String("range4", "", "comma-separated IPv4 CIDRs to scan")
	range6 := flag.String("range6", "", "comma-separated IPv6 CIDRs to scan")
	pingFlag := flag.Bool("ping", true, "Ping each candidate before connect")
	rtt := flag.Bool("rtt", false, "placeholder flag, not used")
	reserved := flag.String("reserved", "", "placeholder flag, not used")
	scanPerIP := flag.Duration("scan-timeout", 5*time.Second, "Per-endpoint scan timeout (dial+handshake)")
	scanMax := flag.Int("scan-max", 30, "Maximum number of endpoints to try during scan")
	// scanVerboseChild := flag.Bool("scan-verbose-child", false, "Print MASQUE child process logs during scan")
	// scanTunnelFailLimit := flag.Int("scan-tunnel-fail-limit", 2, "Number of 'Failed to connect tunnel' occurrences before skipping an endpoint")
	scanOrdered := flag.Bool("scan-ordered", false, "Scan candidates in CIDR order (disable shuffling)")
	testURL := flag.String("test-url", defaultTestURL, "URL used to verify connectivity over the SOCKS tunnel")

	// usque-specific flags
	flag.IntVar(&connectPort, "connect-port", connectPort, "Used port for MASQUE connection")
	flag.StringVar(&dnsStr, "dns", defaultDnsStr, "comma-separated DNS servers to use")
	flag.DurationVar(&dnsTimeout, "dns-timeout", dnsTimeout, "Timeout for DNS queries")
	flag.IntVar(&initialPacketSize, "initial-packet-size", initialPacketSize, "Initial packet size for MASQUE connection")
	flag.DurationVar(&keepalivePeriod, "keepalive-period", keepalivePeriod, "Keepalive period for MASQUE connection")
	flag.BoolVar(&localDns, "local-dns", localDns, "Don't use the tunnel for DNS queries")
	flag.IntVar(&mtu, "mtu", mtu, "MTU for MASQUE connection")
	flag.BoolVar(&noTunnelIpv4, "no-tunnel-ipv4", noTunnelIpv4, "Disable IPv4 inside the MASQUE tunnel")
	flag.BoolVar(&noTunnelIpv6, "no-tunnel-ipv6", noTunnelIpv6, "Disable IPv6 inside the MASQUE tunnel")
	// flag.StringVar(&password, "password", password, "Password for proxy authentication")
	// flag.StringVar(&username, "username", username, "Username for proxy authentication")
	flag.DurationVar(&reconnectDelay, "reconnect-delay", reconnectDelay, "Delay between reconnect attempts")
	flag.StringVar(&sni, "sni", sni, "SNI address to use for MASQUE connection")
	flag.BoolVar(&useIpv6, "ipv6", useIpv6, "Use IPv6 for MASQUE connection")

	flag.Parse()

	_ = rtt
	_ = reserved
	_ = testURL

	if *v4Flag && *v6Flag {
		logErrorAndExit("both -4 and -6 provided")
	}
	if *endpointStr == "" && !*scan {
		logErrorAndExit("--endpoint is required")
	}

	configFile := defaultConfigFile
	usqueConfig.LoadConfig(configFile)

	logutil.Info("running in masque mode", nil)

	if *scan {
		logutil.Info("scanner mode enabled", nil)
		candidates := buildCandidatesFromFlags(*v6Flag, *v4Flag, *range4, *range6)

		if len(candidates) > 1 && !*scanOrdered {
			mrand.Seed(time.Now().UnixNano())
			mrand.Shuffle(len(candidates), func(i, j int) {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			})
		}

		if len(candidates) == 0 {
			chosen, err := pickDefaultEndpoint(*v6Flag)
			if err != nil {
				logErrorAndExit(err.Error())
			}
			*endpointStr = chosen
		} else {
			var dnsAddrs []netip.Addr
			for _, addr := range splitCSV(dnsStr) {
				dnsAddr, err := netip.ParseAddr(addr)
				if err != nil {
					logErrorAndExit(fmt.Sprintf("%v", err))
				}
				dnsAddrs = append(dnsAddrs, dnsAddr)
			}
			var localAddresses []netip.Addr
			if !noTunnelIpv4 {
				v4, err := netip.ParseAddr(usqueConfig.AppConfig.IPv4)
				if err != nil {
					logErrorAndExit(fmt.Sprintf("%v", err))
				}
				localAddresses = append(localAddresses, v4)
			}
			if !noTunnelIpv6 {
				v6, err := netip.ParseAddr(usqueConfig.AppConfig.IPv6)
				if err != nil {
					logErrorAndExit(fmt.Sprintf("%v", err))
				}
				localAddresses = append(localAddresses, v6)
			}
			privKey, err := usqueConfig.AppConfig.GetEcPrivateKey()
			if err != nil {
				logErrorAndExit(fmt.Sprintf("%v", err))
			}

			peerPubKey, err := usqueConfig.AppConfig.GetEcEndpointPublicKey()
			if err != nil {
				logErrorAndExit(fmt.Sprintf("%v", err))
			}

			chosen, err := scanner.TryCandidates(
				candidates,
				netutil.MasqueConfig{
					PrivKey:           privKey,
					PeerPubKey:        peerPubKey,
					LocalAddresses:    localAddresses,
					UseIpv6:           useIpv6,
					SNI:               sni,
					DnsAddrs:          dnsAddrs,
					MTU:               mtu,
					InitialPacketSize: uint16(initialPacketSize),
					KeepalivePeriod:   keepalivePeriod,
					ReconnectDelay:    reconnectDelay,
					DnsTimeout:        dnsTimeout,
					LocalDns:          localDns,
				},
				*scanMax,
				*pingFlag,
				3*time.Second,
				*scanPerIP,
				*testURL,
			)
			if err != nil {
				logErrorAndExit(err.Error())
			}
			*endpointStr = chosen
		}
	} else {
		host, port, err := parseEndpoint(*endpointStr)
		if err != nil {
			logErrorAndExit(fmt.Sprintf("invalid endpoint: %v", err))
		}
		ip := net.ParseIP(host)
		if ip != nil {
			isV6 := ip.To4() == nil
			if useIpv6 != isV6 {
				logutil.Info(fmt.Sprintf("warning: endpoint is IPv%d but --ipv6=%v; overriding to match endpoint", map[bool]int{true: 6, false: 4}[isV6], useIpv6), nil)
				useIpv6 = isV6
			}
		} else if sni == defaultSNI {
			sni = host
		}
		if port != "" {
			p, err := strconv.Atoi(port)
			if err == nil {
				connectPort = p
			}
		}
	}

	bindIP, bindPort := mustSplitBind(*bind)

	if needRegister(configFile, *renew) {
		if err := runRegister(configFile); err != nil {
			logErrorAndExit(fmt.Sprintf("failed to register: %v", err))
		}
	}
	logutil.Info("successfully loaded masque identity", nil)

	cfg := make(map[string]interface{})
	if data, err := os.ReadFile(configFile); err == nil {
		_ = json.Unmarshal(data, &cfg)
	}

	addEndpointToConfig(cfg, *endpointStr)

	if err := writeConfig(configFile, cfg); err != nil {
		logErrorAndExit(fmt.Sprintf("failed to write config: %v", err))
	}

	logConfig(*endpointStr, bindIP, bindPort)

	var dnsAddrs []netip.Addr
	for _, addr := range splitCSV(dnsStr) {
		dnsAddr, err := netip.ParseAddr(addr)
		if err != nil {
			logErrorAndExit(fmt.Sprintf("%v", err))
		}
		dnsAddrs = append(dnsAddrs, dnsAddr)
	}
	var localAddresses []netip.Addr
	if !noTunnelIpv4 {
		v4, err := netip.ParseAddr(usqueConfig.AppConfig.IPv4)
		if err != nil {
			logErrorAndExit(fmt.Sprintf("%v", err))
		}
		localAddresses = append(localAddresses, v4)
	}
	if !noTunnelIpv6 {
		v6, err := netip.ParseAddr(usqueConfig.AppConfig.IPv6)
		if err != nil {
			logErrorAndExit(fmt.Sprintf("%v", err))
		}
		localAddresses = append(localAddresses, v6)
	}
	var endpoint *net.UDPAddr
	if useIpv6 {
		endpoint = &net.UDPAddr{
			IP:   net.ParseIP(usqueConfig.AppConfig.EndpointV6),
			Port: connectPort,
		}
	} else {
		endpoint = &net.UDPAddr{
			IP:   net.ParseIP(usqueConfig.AppConfig.EndpointV4),
			Port: connectPort,
		}
	}
	privKey, err := usqueConfig.AppConfig.GetEcPrivateKey()
	if err != nil {
		logErrorAndExit(fmt.Sprintf("%v", err))
	}

	peerPubKey, err := usqueConfig.AppConfig.GetEcEndpointPublicKey()
	if err != nil {
		logErrorAndExit(fmt.Sprintf("%v", err))
	}

	socksConfiguration := netutil.SocksConfig{
		BindIP:   bindIP,
		BindPort: bindPort,
		MasqueConfig: netutil.MasqueConfig{
			PrivKey:           privKey,
			PeerPubKey:        peerPubKey,
			LocalAddresses:    localAddresses,
			Endpoint:          endpoint,
			UseIpv6:           useIpv6,
			SNI:               sni,
			DnsAddrs:          dnsAddrs,
			MTU:               mtu,
			InitialPacketSize: uint16(initialPacketSize),
			KeepalivePeriod:   keepalivePeriod,
			ReconnectDelay:    reconnectDelay,
			DnsTimeout:        dnsTimeout,
			LocalDns:          localDns,
		},
	}
	if err := netutil.RunMasqueSocks(socksConfiguration, *connectTimeout); err != nil {
		logErrorAndExit(fmt.Sprintf("SOCKS start failed: %v", err))
	}
}

// ------------------------ Helpers ------------------------
func buildCandidatesFromFlags(v6, v4 bool, r4csv, r6csv string) []string {
	ports := []string{
		"443",
		//"500",
		//"1701",
		//"4500",
		//"4443",
		//"8443",
		//"8095",
	}

	var r4, r6 []string
	if strings.TrimSpace(r4csv) != "" {
		r4 = splitCSV(r4csv)
	} else {
		r4 = append([]string{}, defaultRange4...)
	}
	if strings.TrimSpace(r6csv) != "" {
		r6 = splitCSV(r6csv)
	} else {
		r6 = append([]string{}, defaultRange6...)
	}

	ver := scanner.Any
	if v6 {
		ver = scanner.V6
	} else if v4 {
		ver = scanner.V4
	}

	cands, err := scanner.BuildCandidates(ver, r4, r6, ports)
	if err != nil {
		logutil.Info(fmt.Sprintf("scanner.BuildCandidates error: %v", err), nil)
		return nil
	}
	return cands
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func pickDefaultEndpoint(v6 bool) (string, error) {
	pool := defaultV4
	if v6 {
		pool = defaultV6
	}
	if len(pool) == 0 {
		return "", fmt.Errorf("no default endpoints available")
	}
	nBig, _ := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
	return pool[nBig.Int64()], nil
}

func splitBind(b string) (string, string, error) {
	parts := strings.Split(b, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("--bind must be in format IP:Port")
	}
	if err := validatePort(parts[1]); err != nil {
		return "", "", err
	}
	return parts[0], parts[1], nil
}

func mustSplitBind(b string) (string, string) {
	bindIP, bindPort, err := splitBind(b)
	if err != nil {
		logErrorAndExit(err.Error())
	}
	return bindIP, bindPort
}

func validatePort(p string) error {
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q", p)
	}
	return nil
}

func writeConfig(path string, cfg map[string]interface{}) error {
	data, _ := json.MarshalIndent(cfg, "", "  ")
	return os.WriteFile(path, data, 0644)
}

func logConfig(endpoint, bindIP, bindPort string) {
	fields := map[string]string{
		"endpoint":     endpoint,
		"bind":         fmt.Sprintf("%s:%s", bindIP, bindPort),
		"sni":          sni,
		"connect-port": strconv.Itoa(connectPort),
		"ipv6":         strconv.FormatBool(useIpv6),
		"dns":          dnsStr,
		"dns-timeout":  dnsTimeout.String(),
		"mtu":          strconv.Itoa(mtu),
		"keepalive":    keepalivePeriod.String(),
	}
	logutil.Info("starting usque with configuration", fields)
}

// ------------------------ Endpoint ------------------------

func parseEndpoint(ep string) (host, port string, err error) {
	if ep == "" {
		return "", "", fmt.Errorf("empty endpoint")
	}

	if strings.HasPrefix(ep, "[") {
		end := strings.LastIndex(ep, "]")
		if end == -1 {
			return "", "", fmt.Errorf("invalid IPv6 format")
		}
		host = ep[1:end]
		if len(ep) > end+1 && ep[end+1] == ':' {
			port = ep[end+2:]
		}
	} else {
		colon := strings.LastIndex(ep, ":")
		if colon != -1 {
			host = ep[:colon]
			port = ep[colon+1:]
		} else {
			host = ep
		}
	}

	if port != "" {
		if err := validatePort(port); err != nil {
			return "", "", err
		}
	}

	return host, port, nil
}

func addEndpointToConfig(cfg map[string]interface{}, endpoint string) {
	if endpoint == "" {
		return
	}

	host, port, err := parseEndpoint(endpoint)
	if err != nil {
		logErrorAndExit(fmt.Sprintf("invalid endpoint: %v", err))
	}

	if port == "" {
		port = "443"
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			cfg["endpoint_v4"] = host
			cfg["endpoint_v4_port"] = port
			logutil.Info("using IPv4 endpoint", nil)
		} else {
			cfg["endpoint_v6"] = host
			cfg["endpoint_v6_port"] = port
			logutil.Info("using IPv6 endpoint", nil)
		}
		return
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		logErrorAndExit(fmt.Sprintf("failed to resolve %s: %v", host, err))
	}
	if len(ips) == 0 {
		logErrorAndExit(fmt.Sprintf("no IPs for %s", host))
	}

	var chosen net.IP
	hasV4, hasV6 := false, false
	for _, i := range ips {
		if i.To4() != nil {
			hasV4 = true
		} else {
			hasV6 = true
		}
	}

	preferV6 := useIpv6
	if preferV6 && !hasV6 {
		preferV6 = false
	} else if !preferV6 && !hasV4 {
		preferV6 = true
	}

	for _, i := range ips {
		if (preferV6 && i.To4() == nil) || (!preferV6 && i.To4() != nil) {
			chosen = i
			break
		}
	}
	if chosen == nil {
		chosen = ips[0]
	}

	isV6 := chosen.To4() == nil
	version := "v4"
	if isV6 {
		version = "v6"
	}
	cfg["endpoint_"+version] = chosen.String()
	cfg["endpoint_"+version+"_port"] = port
	logutil.Info(fmt.Sprintf("using resolved IPv%s endpoint for %s", map[bool]string{true: "6", false: "4"}[isV6], host), nil)
}

func needRegister(configFile string, renew bool) bool {
	if renew {
		return true
	}
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return true
	}
	return false
}

// ------------------------ Process & Scanner ------------------------

func runRegister(configFile string) error {
	accountData, err := api.Register(defaultModel, defaultLocale, "", true)
	if err != nil {
		return err
	}
	privKey, pubKey, err := cryptoutil.GenerateEcKeyPair()
	if err != nil {
		return err
	}
	updatedAccountData, apiErr, err := api.EnrollKey(accountData, pubKey, "masque-plus")
	if err != nil {
		if apiErr != nil {
			return fmt.Errorf("(API Errors: %s) %s", apiErr.ErrorsAsString("; "), err)
		}
		return err
	}
	usqueConfig.AppConfig = usqueConfig.Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(privKey),
		EndpointV4:     updatedAccountData.Config.Peers[0].Endpoint.V4[:len(updatedAccountData.Config.Peers[0].Endpoint.V4)-2],
		EndpointV6:     updatedAccountData.Config.Peers[0].Endpoint.V6[1 : len(updatedAccountData.Config.Peers[0].Endpoint.V6)-3],
		EndpointPubKey: updatedAccountData.Config.Peers[0].PublicKey,
		License:        updatedAccountData.Account.License,
		ID:             updatedAccountData.ID,
		AccessToken:    accountData.Token,
		IPv4:           updatedAccountData.Config.Interface.Addresses.V4,
		IPv6:           updatedAccountData.Config.Interface.Addresses.V6,
	}
	return usqueConfig.AppConfig.SaveConfig(configFile)
}

// ------------------------ Logging ------------------------

func logErrorAndExit(msg string) {
	logutil.Error(msg, nil)
	os.Exit(1)
}
