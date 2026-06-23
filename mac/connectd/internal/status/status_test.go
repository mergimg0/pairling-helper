package status

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func hasRouteKind(routes []AdvertisedRoute, kind string) bool {
	for _, r := range routes {
		if r.Kind == kind {
			return true
		}
	}
	return false
}

func TestFunnelRouteIsAdditiveAndGated(t *testing.T) {
	s := NewStore("pairling-test")
	s.SetListenerRunning(true)
	s.SetUpstreamReachable(true)
	s.SetTailnetIP("100.64.0.1")
	s.SetAuthenticated()

	// Funnel disabled: only the tailnet route, and no funnel_hostname in the JSON.
	snap := s.Snapshot()
	if hasRouteKind(snap.AdvertisedRoutes, RouteKindFunnel) {
		t.Error("funnel route present while funnel disabled")
	}
	js, _ := json.Marshal(snap)
	if strings.Contains(string(js), "funnel_hostname") {
		t.Error("funnel_hostname must be omitted when empty")
	}

	// Enable funnel: the route appears with an https base URL and a lower priority.
	s.SetFunnelHostname("pairling-abc.tail1234.ts.net")
	snap = s.Snapshot()
	var funnel, tailnet *AdvertisedRoute
	for i := range snap.AdvertisedRoutes {
		switch snap.AdvertisedRoutes[i].Kind {
		case RouteKindFunnel:
			funnel = &snap.AdvertisedRoutes[i]
		case RouteKindTailnet:
			tailnet = &snap.AdvertisedRoutes[i]
		}
	}
	if funnel == nil || tailnet == nil {
		t.Fatalf("expected tailnet and funnel routes, got %+v", snap.AdvertisedRoutes)
	}
	if funnel.BaseURL != "https://pairling-abc.tail1234.ts.net" {
		t.Errorf("funnel base_url = %q", funnel.BaseURL)
	}
	if funnel.Priority >= tailnet.Priority {
		t.Errorf("funnel priority %d must be below tailnet priority %d", funnel.Priority, tailnet.Priority)
	}

	// Unhealthy node: no routes advertise, even with a funnel hostname set.
	s.SetUpstreamReachable(false)
	if len(s.Snapshot().AdvertisedRoutes) != 0 {
		t.Error("no routes should advertise when the node is unhealthy")
	}
}

func TestStoreServesHelperReadableSnapshotWithoutSecrets(t *testing.T) {
	store := NewStore("pairling-inst-abcdef")
	store.SetAuthPending("https://login.tailscale.com/a/secret-auth-token")
	store.SetTailnetIP("100.64.0.10")
	store.SetUpstreamReachable(true)
	store.SetListenerRunning(true)
	store.SetLastError("provider key sk-secret leaked elsewhere")

	rec := httptest.NewRecorder()
	store.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body Snapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Hostname != "pairling-inst-abcdef" || body.TailnetIP != "100.64.0.10" {
		t.Fatalf("bad snapshot: %+v", body)
	}
	if body.SchemaVersion != 2 || body.AuthState != "pending" || !body.AuthURLPresent || !body.UpstreamReachable || !body.ListenerRunning {
		t.Fatalf("bad status fields: %+v", body)
	}
	if body.TailnetIPCount != 1 || body.ControlURLMode != DefaultControlURLMode || body.ListenPort != DefaultListenPort {
		t.Fatalf("bad v2 status fields: %+v", body)
	}
	if len(body.AdvertisedRoutes) != 0 {
		t.Fatalf("pending auth should not advertise routes: %+v", body.AdvertisedRoutes)
	}
	raw := rec.Body.String()
	for _, forbidden := range []string{"secret-auth-token", "sk-secret"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("status leaked %q: %s", forbidden, raw)
		}
	}
}

func TestSnapshotSerializesTailnetIdentityFields(t *testing.T) {
	store := NewStore("pairling-inst-abcdef")
	store.SetTailnetIdentity("nXb6CNTRL", []string{"tag:pairling-connect"}, []string{"100.79.217.7"})

	raw, err := json.Marshal(store.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{
		`"tailnet_node_id":"nXb6CNTRL"`,
		`"tags":["tag:pairling-connect"]`,
		`"tailnet_ips":["100.79.217.7"]`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("snapshot missing %s: %s", want, body)
		}
	}
}

func TestSnapshotSerializesKnownTailnetLockStatus(t *testing.T) {
	store := NewStore("pairling-inst-abcdef")
	store.SetTailnetLockEnabled(false)

	raw, err := json.Marshal(store.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if !strings.Contains(body, `"tailnet_lock_enabled":false`) {
		t.Fatalf("snapshot missing known lock status: %s", body)
	}
}

func TestSnapshotOmitsTailnetIdentityWhenUnknown(t *testing.T) {
	raw, err := json.Marshal(NewStore("pairling-inst-abcdef").Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, forbidden := range []string{"tailnet_node_id", "tags", "tailnet_ips"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("fresh snapshot should omit %q: %s", forbidden, body)
		}
	}
	if !strings.Contains(body, `"auth_state":"starting"`) {
		t.Fatalf("fresh snapshot lost coherent auth state: %s", body)
	}
}

func TestSetTailnetIdentityIsIdempotentAndReplaces(t *testing.T) {
	store := NewStore("pairling-inst-abcdef")
	store.SetTailnetIdentity("old-node", []string{"tag:old"}, []string{"100.64.0.1"})
	store.SetTailnetIdentity("new-node", []string{"tag:pairling-connect"}, []string{"100.79.217.7", "fd7a:115c:a1e0::1"})

	snapshot := store.Snapshot()
	if snapshot.TailnetNodeID != "new-node" {
		t.Fatalf("node ID = %q, want new-node", snapshot.TailnetNodeID)
	}
	if got, want := strings.Join(snapshot.Tags, ","), "tag:pairling-connect"; got != want {
		t.Fatalf("tags = %q, want %q", got, want)
	}
	if got, want := strings.Join(snapshot.TailnetIPs, ","), "100.79.217.7,fd7a:115c:a1e0::1"; got != want {
		t.Fatalf("tailnet IPs = %q, want %q", got, want)
	}
}

func TestTailnetIdentityCarriesNoSecrets(t *testing.T) {
	store := NewStore("pairling-inst-abcdef")
	store.SetTailnetIdentity("tskey-auth-example", []string{"AuthKey=bad"}, []string{"NLPrivate=bad"})

	raw, err := json.Marshal(store.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, forbidden := range []string{"tskey", "authkey", "AuthKey", "NLPrivate"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("tailnet identity leaked %q: %s", forbidden, body)
		}
	}
}

func TestStoreAdvertisesRouteOnlyWhenReady(t *testing.T) {
	store := NewStore("pairling-inst-abcdef")
	store.SetAuthPending("open https://login.tailscale.com/a/example-token")
	store.SetListenPort(7773)
	store.SetTailnetIP("100.64.0.10")
	store.SetListenerRunning(true)
	store.SetUpstreamReachable(true)

	if got := store.Snapshot().AdvertisedRoutes; len(got) != 0 {
		t.Fatalf("unauthenticated status advertised routes: %+v", got)
	}

	store.SetAuthenticated()
	snapshot := store.Snapshot()
	if len(snapshot.AdvertisedRoutes) != 1 {
		t.Fatalf("advertised routes = %+v, want one ready route", snapshot.AdvertisedRoutes)
	}
	route := snapshot.AdvertisedRoutes[0]
	if route.ID != RouteIDPairlingConnect || route.Source != RouteSourceConnectd || route.Kind != RouteKindTailnet {
		t.Fatalf("bad route identity: %+v", route)
	}
	if route.BaseURL != "http://100.64.0.10:7773" || route.Host != "100.64.0.10" || route.Port != 7773 || route.Status != RouteStatusReady {
		t.Fatalf("bad route fields: %+v", route)
	}
	if snapshot.AuthURLPresent {
		t.Fatalf("authenticated snapshot should clear auth URL presence: %+v", snapshot)
	}
	if authURL, ok := store.AuthURLForOpen(); ok || authURL != "" {
		t.Fatalf("authenticated status should clear raw auth URL, got ok=%t url=%q", ok, authURL)
	}
}

func TestStoreSuppressesAdvertisedRouteAfterRecentGatewayValidationFailure(t *testing.T) {
	store := NewStore("pairling-inst-abcdef")
	store.SetAuthenticated()
	store.SetTailnetIP("100.64.0.10")
	store.SetListenerRunning(true)
	store.SetUpstreamReachable(true)

	store.RecordGatewayEvent("GET", "/routez", 502, "upstream_error")
	snapshot := store.Snapshot()
	if snapshot.GatewayHealthy {
		t.Fatalf("gateway should be unhealthy after route validation failure: %+v", snapshot)
	}
	if snapshot.LastGatewayFailure == "" {
		t.Fatalf("gateway failure should be exposed as redacted diagnostic: %+v", snapshot)
	}
	if got := snapshot.AdvertisedRoutes; len(got) != 0 {
		t.Fatalf("gateway failure advertised routes: %+v", got)
	}

	store.RecordGatewayEvent("GET", "/routez", 200, "forwarded")
	snapshot = store.Snapshot()
	if !snapshot.GatewayHealthy {
		t.Fatalf("gateway should recover after fresh successful routez proof: %+v", snapshot)
	}
	if len(snapshot.AdvertisedRoutes) != 1 {
		t.Fatalf("recovered gateway did not advertise route: %+v", snapshot.AdvertisedRoutes)
	}
}

func TestStoreDoesNotPoisonRouteHealthForProductEndpointFailures(t *testing.T) {
	store := NewStore("pairling-inst-abcdef")
	store.SetAuthenticated()
	store.SetTailnetIP("100.64.0.10")
	store.SetListenerRunning(true)
	store.SetUpstreamReachable(true)

	store.RecordGatewayEvent("POST", "/push/test", 500, "upstream_error")
	snapshot := store.Snapshot()
	if !snapshot.GatewayHealthy {
		t.Fatalf("product endpoint 5xx should not poison route health: %+v", snapshot)
	}
	if snapshot.LastGatewayFailure != "" {
		t.Fatalf("product endpoint failure should not be stored as route failure: %+v", snapshot)
	}
	if len(snapshot.AdvertisedRoutes) != 1 {
		t.Fatalf("product endpoint failure should not suppress advertised routes: %+v", snapshot.AdvertisedRoutes)
	}
}

func TestStoreRecoversRouteHealthAfterFreshSuccessfulRouteProof(t *testing.T) {
	store := NewStore("pairling-inst-abcdef")
	store.SetAuthenticated()
	store.SetTailnetIP("100.64.0.10")
	store.SetListenerRunning(true)
	store.SetUpstreamReachable(true)

	store.RecordGatewayEvent("GET", "/routez", 502, "upstream_error")
	if store.Snapshot().GatewayHealthy {
		t.Fatalf("route proof failure should mark route unhealthy")
	}

	store.RecordGatewayEvent("GET", "/routez", 200, "forwarded")
	snapshot := store.Snapshot()
	if !snapshot.GatewayHealthy {
		t.Fatalf("fresh routez proof should recover route health: %+v", snapshot)
	}
	if len(snapshot.AdvertisedRoutes) != 1 {
		t.Fatalf("fresh routez proof should restore advertised route: %+v", snapshot.AdvertisedRoutes)
	}
}

func TestStoreKeepsRawAuthURLPrivateForLocalOpenOnly(t *testing.T) {
	store := NewStore("pairling-inst-abcdef")
	rawAuthURL := "https://login.tailscale.com/a/secret-auth-token?next=pairling"
	store.SetAuthPending("Approve Pairling Connect at " + rawAuthURL)

	authURL, ok := store.AuthURLForOpen()
	if !ok || authURL != rawAuthURL {
		t.Fatalf("auth URL for local open = %q, %t; want raw in-memory URL", authURL, ok)
	}

	rec := httptest.NewRecorder()
	store.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	if strings.Contains(rec.Body.String(), "secret-auth-token") || strings.Contains(rec.Body.String(), "login.tailscale.com/a/") {
		t.Fatalf("status response leaked raw auth URL: %s", rec.Body.String())
	}
}

func TestStoreRejectsInvalidAuthURLForLocalOpen(t *testing.T) {
	store := NewStore("pairling-inst-abcdef")
	store.SetAuthPending("Approve Pairling Connect at http://login.tailscale.com/a/not-secure")

	if authURL, ok := store.AuthURLForOpen(); ok || authURL != "" {
		t.Fatalf("invalid auth URL should not be available for local open, got ok=%t url=%q", ok, authURL)
	}

	snapshot := store.Snapshot()
	if snapshot.AuthURLPresent {
		t.Fatalf("invalid auth URL should not set presence: %+v", snapshot)
	}
	if !ValidAuthURL("https://login.tailscale.com/a/example-token?next=pairling") {
		t.Fatal("valid auth URL was rejected")
	}
	if ValidAuthURL("https://login.tailscale.com.evil/a/example-token") {
		t.Fatal("evil host was accepted")
	}
}

func TestStoreSuppressesAdvertisedRouteForDegradedStates(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*Store)
	}{
		{
			name: "auth pending",
			configure: func(store *Store) {
				store.SetAuthPending("open https://login.tailscale.com/a/example")
				store.SetTailnetIP("100.64.0.10")
				store.SetListenerRunning(true)
				store.SetUpstreamReachable(true)
			},
		},
		{
			name: "missing tailnet IP",
			configure: func(store *Store) {
				store.SetAuthenticated()
				store.SetListenerRunning(true)
				store.SetUpstreamReachable(true)
			},
		},
		{
			name: "listener down",
			configure: func(store *Store) {
				store.SetAuthenticated()
				store.SetTailnetIP("100.64.0.10")
				store.SetUpstreamReachable(true)
			},
		},
		{
			name: "upstream down",
			configure: func(store *Store) {
				store.SetAuthenticated()
				store.SetTailnetIP("100.64.0.10")
				store.SetListenerRunning(true)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := NewStore("pairling-inst-abcdef")
			tc.configure(store)
			if got := store.Snapshot().AdvertisedRoutes; len(got) != 0 {
				t.Fatalf("degraded state advertised routes: %+v", got)
			}
		})
	}
}

func TestRedactRemovesAuthURLsAndBearerMaterial(t *testing.T) {
	cases := map[string][]string{
		"open https://login.tailscale.com/a/abc123DEF456 to authenticate": {
			"abc123DEF456",
		},
		"Authorization: Bearer device-token-value": {
			"device-token-value",
		},
		"auth key tskey-auth-k9uFq_secret_part": {
			"tskey-auth-k9uFq_secret_part",
		},
	}

	for input, forbidden := range cases {
		t.Run(input, func(t *testing.T) {
			redacted := Redact(input)
			for _, value := range forbidden {
				if strings.Contains(redacted, value) {
					t.Fatalf("redacted output leaked %q: %s", value, redacted)
				}
			}
		})
	}
}
