package main

// SPEC-p5 §2.1 — the SSH gateway: a third listener on loopback 7775 running
// the SAME gateway Handler in ExposureModeSSH. The SSH tunnel's remote end
// targets 7775 and nothing else; the perimeter holds identically because it
// IS the perimeter — no fifth allowlist copy exists.

import (
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"dev.pairling/connectd/internal/gateway"
)

// sshGatewayEnabledFromEnv parses PAIRLING_SSH_GATEWAY. Off by default;
// `pairling setup --ssh` writes the LaunchAgent env that turns it on.
func sshGatewayEnabledFromEnv(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}

// newSSHGatewayHandler builds the ExposureModeSSH gateway handler after
// refusing any non-loopback bind address: the tunnel's remote end is the
// only intended client, so 7775 never faces a network.
func newSSHGatewayHandler(upstream *url.URL, maxBodyBytes int64, addr string) (*gateway.Handler, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if !loopbackHost(host) {
		return nil, errors.New("ssh gateway must bind loopback only")
	}
	return gateway.NewHandler(gateway.Options{
		Upstream:     upstream,
		MaxBodyBytes: maxBodyBytes,
		Mode:         gateway.ExposureModeSSH,
		RateLimiter:  gateway.NewMemoryRateLimiter(20, 5*time.Minute),
	})
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
