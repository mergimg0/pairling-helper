package main

// SPEC-p5 §2.1 — the SSH gateway listener: loopback 127.0.0.1:7775 running
// the same gateway Handler in ExposureModeSSH, off by default. Binding
// anywhere but loopback is refused — the tunnel's remote end is the ONLY
// intended client.

import (
	"net/url"
	"testing"
)

func TestSSHGatewayRefusesNonLoopbackBind(t *testing.T) {
	upstream, _ := url.Parse("http://127.0.0.1:7773")
	for _, addr := range []string{"0.0.0.0:7775", ":7775", "192.168.1.10:7775", "[::]:7775"} {
		if _, err := newSSHGatewayHandler(upstream, 1024, addr, nil); err == nil {
			t.Fatalf("ssh gateway must refuse non-loopback bind %q", addr)
		}
	}
}

func TestSSHGatewayBuildsHandlerInSSHMode(t *testing.T) {
	upstream, _ := url.Parse("http://127.0.0.1:7773")
	for _, addr := range []string{"127.0.0.1:7775", "localhost:7775", "[::1]:7775"} {
		handler, err := newSSHGatewayHandler(upstream, 1024, addr, nil)
		if err != nil {
			t.Fatalf("loopback bind %q rejected: %v", addr, err)
		}
		if handler == nil {
			t.Fatalf("no handler for %q", addr)
		}
	}
}

func TestSSHGatewayEnabledDefaultsOff(t *testing.T) {
	if sshGatewayEnabledFromEnv("") {
		t.Fatal("ssh gateway must default off")
	}
	if sshGatewayEnabledFromEnv("0") || sshGatewayEnabledFromEnv("off") || sshGatewayEnabledFromEnv("false") {
		t.Fatal("explicit off values must stay off")
	}
	if !sshGatewayEnabledFromEnv("1") || !sshGatewayEnabledFromEnv("true") || !sshGatewayEnabledFromEnv("on") {
		t.Fatal("explicit on values must enable")
	}
}
