package httpcheck

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"masque-plus/internal/logutil"

	"github.com/things-go/go-socks5"
	"golang.org/x/net/proxy"
)

// ResultStatus is the final outcome of the check.
type ResultStatus string

const (
	StatusOK       ResultStatus = "OK"        // "warp=on" found in body
	StatusNoWarp   ResultStatus = "NO_WARP"   // request succeeded but "warp=on" not found
	StatusHTTPFail ResultStatus = "HTTP_FAIL" // HTTP-layer failure (non-200, read error, etc.)
	StatusConnFail ResultStatus = "CONN_FAIL" // connection/proxy/dial error
)

// CheckWarpOverSocks dials through a SOCKS5 proxy at `bind`, GETs `url`, and looks for "warp=on" in the body.
// It logs structured messages via logutil and returns a ResultStatus and error.
func CheckWarpOverSocks(bind, url string, timeout time.Duration) (ResultStatus, error) {
	start := time.Now()

	logutil.Info("warp check start", map[string]string{
		"bind":    bind,
		"url":     url,
		"timeout": timeout.String(),
	})

	dialer, err := proxy.SOCKS5("tcp", bind, nil, proxy.Direct)
	if err != nil {
		logutil.Error("socks5 dialer error", map[string]string{
			"bind":    bind,
			"elapsed": time.Since(start).String(),
			"error":   err.Error(),
		})
		return StatusConnFail, fmt.Errorf("socks5 dialer error: %w", err)
	}
	return CheckWarpOverDialer(dialer, url, nil, timeout)
}

func CheckWarpOverDialer(dialer proxy.Dialer, url string, resolver socks5.NameResolver, timeout time.Duration) (ResultStatus, error) {
	start := time.Now()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if resolver != nil {
				host, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, fmt.Errorf("resolve error: %v", err)
				}
				_, resolvedIp, err := resolver.Resolve(ctx, host)
				if err != nil {
					return nil, fmt.Errorf("resolve error: %v", err)
				}
				address = resolvedIp.String() + ":" + port
			}
			return dialer.Dial(network, address)
		},
		TLSHandshakeTimeout: timeout,
		Proxy:               nil, // disable env proxy
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		logutil.Error("http request build error", map[string]string{
			"url":     url,
			"elapsed": time.Since(start).String(),
			"error":   err.Error(),
		})
		return StatusHTTPFail, fmt.Errorf("build request error: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		logutil.Error("http request error", map[string]string{
			"url":     url,
			"elapsed": time.Since(start).String(),
			"error":   err.Error(),
		})
		return StatusHTTPFail, fmt.Errorf("http request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logutil.Warn("unexpected http status", map[string]string{
			"url":         url,
			"status_code": fmt.Sprintf("%d", resp.StatusCode),
			"status":      resp.Status,
			"elapsed":     time.Since(start).String(),
		})
		return StatusHTTPFail, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap at 1 MiB to be safe
	if err != nil {
		logutil.Error("read body error", map[string]string{
			"url":         url,
			"status_code": fmt.Sprintf("%d", resp.StatusCode),
			"elapsed":     time.Since(start).String(),
			"error":       err.Error(),
		})
		return StatusHTTPFail, fmt.Errorf("read body error: %w", err)
	}

	found := strings.Contains(strings.ToLower(string(body)), "warp=on")

	kv := map[string]string{
		"url":         url,
		"status_code": fmt.Sprintf("%d", resp.StatusCode),
		"bytes":       fmt.Sprintf("%d", len(body)),
		"elapsed":     time.Since(start).String(),
	}

	if found {
		logutil.Info("warp check success", merge(kv, map[string]string{
			"result": string(StatusOK),
		}))
		return StatusOK, nil
	}

	logutil.Info("warp check finished - no warp", merge(kv, map[string]string{
		"result": string(StatusNoWarp),
	}))
	return StatusNoWarp, nil

}

// merge merges two string maps.
func merge(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}
