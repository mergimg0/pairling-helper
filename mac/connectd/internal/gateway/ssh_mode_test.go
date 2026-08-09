package gateway

// SPEC-p5 §2.1 — SSH terminates at a gateway, never at the daemon. The SSH
// listener runs the SAME Handler in ExposureModeSSH: the post-pair
// allowlist minus the /pair/* lifecycle, bearer required, headers scrubbed,
// provenance ssh_gateway injected. The §1 trap list is the contract: a raw
// port-forward exposed all of these; the gateway exposes none.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSSHModeAllowsPostPairSurfaceWithBearerOnly(t *testing.T) {
	var forwarded []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = append(forwarded, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	handler := newTestHandlerWithMode(t, upstream.URL, 1024, nil, ExposureModeSSH, nil)

	// No bearer: the post-pair surface does not exist.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://ssh.local/sessions", nil))
	if rec.Code == http.StatusOK {
		t.Fatalf("bearer-less GET /sessions must be rejected, got %d", rec.Code)
	}

	// With bearer: allowlisted reads and writes flow.
	for _, probe := range []struct {
		method, path string
	}{
		{http.MethodGet, "/sessions"},
		{http.MethodPost, "/send-text"},
	} {
		req := httptest.NewRequest(probe.method, "http://ssh.local"+probe.path, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer device-token")
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("authorized %s %s status = %d body = %s", probe.method, probe.path, rec.Code, rec.Body.String())
		}
	}
	if len(forwarded) != 2 {
		t.Fatalf("forwarded = %+v", forwarded)
	}
}

func TestSSHModeBlocksTheTrapListEvenWithBearer(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("trap path reached the daemon: %s %s", r.Method, r.URL.Path)
	}))
	defer upstream.Close()
	handler := newTestHandlerWithMode(t, upstream.URL, 1024, nil, ExposureModeSSH, nil)

	// Pairing over SSH does not exist — lifecycle AND claim paths blocked.
	// The loopback trust tier and connectd's own control surface stay
	// unreachable, and escaped separators never resolve.
	traps := []struct {
		method, path string
	}{
		{http.MethodPost, "/pair/start"},
		{http.MethodPost, "/pair/claim"},
		{http.MethodPost, "/pair/psk-activate"},
		{http.MethodPost, "/pair/psk-claim"},
		{http.MethodPost, "/pair/psk-claim-v2"},
		{http.MethodPost, "/pair/revoke"},
		{http.MethodPost, "/pair/rotate-token"},
		{http.MethodPost, "/pair/bind-node"},
		{http.MethodPost, "/internal/session-register"},
		{http.MethodGet, "/auth/open"},
		{http.MethodGet, "/sessions%2fescape"},
		{http.MethodGet, "/sessions%5cescape"},
	}
	for _, trap := range traps {
		req := httptest.NewRequest(trap.method, "http://ssh.local"+trap.path, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer device-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Fatalf("trap %s %s must be blocked at the gateway, got %d", trap.method, trap.path, rec.Code)
		}
	}
}

// SPEC-p5 §2.4: every contract row's connectd_ssh_gateway flag is enforced
// by the live handler — the SSH surface IS the post-pair set minus the
// /pair/* lifecycle, row by row.
func TestSSHModeMatchesEndpointContract(t *testing.T) {
	contract := loadEndpointContractForTesting(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	handler := newTestHandlerWithMode(t, upstream.URL, 1024, nil, ExposureModeSSH, nil)

	exercised := 0
	for _, row := range contract.Rows {
		if !row.AssertConnectdParity {
			continue
		}
		req := httptest.NewRequest(row.Method, "http://ssh.local"+row.SamplePath, strings.NewReader(`{}`))
		// Every SSH request carries a bearer: the mode has no pre-pair set.
		req.Header.Set("Authorization", "Bearer device-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		got := rec.Code == http.StatusOK
		if got != row.ConnectdSSHGateway {
			t.Fatalf("%s %s ssh allowed = %t, want %t (status=%d body=%s)", row.Method, row.SamplePath, got, row.ConnectdSSHGateway, rec.Code, rec.Body.String())
		}
		exercised++
	}
	if exercised == 0 {
		t.Fatal("contract did not exercise any ssh-mode rows")
	}
}

func TestSSHModeScrubsForgedHeadersAndInjectsSSHProvenance(t *testing.T) {
	var peerNode, provenance, gatewayHeader, internalToken string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerNode = r.Header.Get("X-Pairling-Peer-Node")
		provenance = r.Header.Get("X-Pairling-Peer-Provenance")
		gatewayHeader = r.Header.Get("X-Pairling-Connect-Gateway")
		internalToken = r.Header.Get("X-Pairling-Internal-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	handler := newTestHandlerWithMode(t, upstream.URL, 1024, nil, ExposureModeSSH, nil)

	req := httptest.NewRequest(http.MethodPost, "http://ssh.local/send-text", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer device-token")
	req.Header.Set("X-Pairling-Peer-Node", "forged-node")
	req.Header.Set("X-Pairling-Peer-Provenance", "pairling_connectd")
	req.Header.Set("X-Pairling-Connect-Gateway", "forged-gateway")
	req.Header.Set("X-Pairling-Internal-Token", "forged-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if peerNode != "" {
		t.Fatalf("forged peer node forwarded: %q", peerNode)
	}
	if internalToken != testGatewayToken {
		t.Fatalf("internal token = %q, want gateway-owned token", internalToken)
	}
	if provenance != "ssh_gateway" {
		t.Fatalf("provenance = %q, want ssh_gateway (gateway-injected, never client-supplied)", provenance)
	}
	if gatewayHeader != "pairling-connectd" {
		t.Fatalf("gateway header = %q, want the gateway's own value", gatewayHeader)
	}
}
