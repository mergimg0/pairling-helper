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

func proveGatewayReady(store *Store) {
	for range GatewayRecoveryProofs {
		store.RecordGatewayEvent(http.MethodGet, "/routez", http.StatusOK, "route_verified")
	}
}

func TestRouteAvailabilityDependsOnlyOnTailnetState(t *testing.T) {
	store := NewStore("pairling-inst-abcdef")
	store.SetAuthenticated()
	store.SetTailnetIP("100.64.0.10")
	store.SetListenerRunning(true)

	if got := store.Snapshot().AdvertisedRoutes; len(got) != 1 {
		t.Fatalf("authenticated listener should advertise one route: %+v", got)
	}
	store.SetUpstreamReachable(false)
	store.RecordGatewayEvent("GET", "/routez", http.StatusBadGateway, "upstream_error")
	if got := store.Snapshot().AdvertisedRoutes; len(got) != 1 {
		t.Fatalf("application failures must not hide tailnet route identity: %+v", got)
	}
	store.SetTailnetIP("")
	if got := store.Snapshot().AdvertisedRoutes; len(got) != 0 {
		t.Fatalf("missing tailnet identity should remove route: %+v", got)
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
	proveGatewayReady(store)

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






func TestGatewayFailureClassification(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  int
		outcome string
	}{
		{name: "upstream error", status: 502, outcome: "upstream_error"},
		{name: "validation failure", status: 422, outcome: "validation_failed"},
		{name: "timeout", status: 408, outcome: "timeout"},
		{name: "connection refused", status: 0, outcome: "connection_refused"},
		{name: "bad gateway response", status: 502, outcome: "forwarded"},
		{name: "gateway timeout response", status: 504, outcome: "forwarded"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !gatewayEventIsFailure(test.status, test.outcome) {
				t.Fatalf("status=%d outcome=%q should be a gateway failure", test.status, test.outcome)
			}
		})
	}
}

func TestForwardedApplicationResponsesDoNotPoisonGatewayHealth(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
	}{
		{name: "application error", status: 500},
		{name: "runtime load shedding", status: 503},
		{name: "rate limited", status: 429},
		{name: "not found", status: 404},
	} {
		t.Run(test.name, func(t *testing.T) {
			if gatewayEventIsFailure(test.status, "forwarded") {
				t.Fatalf("forwarded status=%d should not mark the gateway unhealthy", test.status)
			}
		})
	}
}

func TestStoreGatewayFailureResetsRecoveryProofStreak(t *testing.T) {
	store := NewStore("pairling-inst-abcdef")
	store.SetAuthenticated()
	store.SetTailnetIP("100.64.0.10")
	store.SetListenerRunning(true)
	store.SetUpstreamReachable(true)
	proveGatewayReady(store)

	store.RecordGatewayEvent("GET", "/routez", 502, "upstream_error")
	if store.Snapshot().GatewayHealthy {
		t.Fatalf("route proof failure should mark route unhealthy")
	}

	store.RecordGatewayEvent("GET", "/routez", 200, "route_verified")
	store.RecordGatewayEvent("GET", "/routez", 502, "upstream_error")
	store.RecordGatewayEvent("GET", "/routez", 200, "route_verified")
	snapshot := store.Snapshot()
	if snapshot.GatewayHealthy {
		t.Fatalf("failure between routez successes should reset recovery streak: %+v", snapshot)
	}

	store.RecordGatewayEvent("GET", "/routez", 200, "route_verified")
	snapshot = store.Snapshot()
	if !snapshot.GatewayHealthy {
		t.Fatalf("two routez successes after latest failure should recover route health: %+v", snapshot)
	}
	if len(snapshot.AdvertisedRoutes) != 1 {
		t.Fatalf("consecutive routez proofs should restore advertised route: %+v", snapshot.AdvertisedRoutes)
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
