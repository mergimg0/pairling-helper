package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMintProducesTaggedPreauthSingleUseShortKey(t *testing.T) {
	var keyRequest map[string]any
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = r.ParseForm()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v2/tailnet/-/keys":
			if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
				t.Fatalf("Authorization header = %q", got)
			}
			if err := json.NewDecoder(r.Body).Decode(&keyRequest); err != nil {
				t.Fatalf("decode key request: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "k-test",
				"key":     "tskey-auth-test",
				"expires": time.Unix(1700000600, 0).Format(time.RFC3339),
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer api.Close()

	dir := t.TempDir()
	b, err := NewBroker(BrokerConfig{
		SecretPath: filepath.Join(dir, "client_secret.json"),
		StatePath:  filepath.Join(dir, "state.json"),
		AuditPath:  filepath.Join(dir, "audit.jsonl"),
		OAuthURL:   api.URL + "/oauth/token",
		APIBaseURL: api.URL + "/api/v2",
		Now:        func() time.Time { return time.Unix(1700000000, 0) },
		LockStatus: func(context.Context) (bool, error) {
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeClientSecret(b.cfg.SecretPath, clientSecret{ClientID: "cid", ClientSecret: "csecret"}); err != nil {
		t.Fatal(err)
	}

	res, err := b.MintPhoneKey(context.Background(), "pair_abc123")
	if err != nil {
		t.Fatalf("MintPhoneKey failed: %v", err)
	}
	if res.AuthKey != "tskey-auth-test" || res.KeyID != "k-test" {
		t.Fatalf("mint response = %+v", res)
	}

	create := keyRequest["capabilities"].(map[string]any)["devices"].(map[string]any)["create"].(map[string]any)
	if create["reusable"] != false || create["ephemeral"] != false || create["preauthorized"] != true {
		t.Fatalf("create caps = %#v", create)
	}
	tags := create["tags"].([]any)
	if len(tags) != 1 || tags[0] != "tag:pairling-phone" {
		t.Fatalf("tags = %#v", tags)
	}
	if got := int(keyRequest["expirySeconds"].(float64)); got > 600 {
		t.Fatalf("expirySeconds = %d, want <= 600", got)
	}
}

func TestMintRejectsSecondMintForSamePairId(t *testing.T) {
	keyPosts := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v2/tailnet/-/keys":
			keyPosts++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "k-test",
				"key":     "tskey-auth-test",
				"expires": time.Unix(1700000600, 0).Format(time.RFC3339),
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer api.Close()

	dir := t.TempDir()
	b, err := NewBroker(BrokerConfig{
		SecretPath: filepath.Join(dir, "client_secret.json"),
		StatePath:  filepath.Join(dir, "state.json"),
		AuditPath:  filepath.Join(dir, "audit.jsonl"),
		OAuthURL:   api.URL + "/oauth/token",
		APIBaseURL: api.URL + "/api/v2",
		Now:        func() time.Time { return time.Unix(1700000000, 0) },
		LockStatus: func(context.Context) (bool, error) {
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeClientSecret(b.cfg.SecretPath, clientSecret{ClientID: "cid", ClientSecret: "csecret"}); err != nil {
		t.Fatal(err)
	}

	if _, err := b.MintPhoneKey(context.Background(), "pair_abc123"); err != nil {
		t.Fatalf("first mint failed: %v", err)
	}
	if _, err := b.MintPhoneKey(context.Background(), "pair_abc123"); err == nil {
		t.Fatal("second mint succeeded, want duplicate pair_id rejection")
	}
	if keyPosts != 1 {
		t.Fatalf("key mint POSTs = %d, want 1", keyPosts)
	}
}

func TestDuplicatePairIDAuditedWithoutKeyMaterial(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v2/tailnet/-/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "k-duplicate",
				"key":     "tskey-auth-duplicate-secret",
				"expires": time.Unix(1700000600, 0).Format(time.RFC3339),
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer api.Close()

	dir := t.TempDir()
	b, err := NewBroker(BrokerConfig{
		SecretPath: filepath.Join(dir, "client_secret.json"),
		StatePath:  filepath.Join(dir, "state.json"),
		AuditPath:  filepath.Join(dir, "audit.jsonl"),
		OAuthURL:   api.URL + "/oauth/token",
		APIBaseURL: api.URL + "/api/v2",
		Now:        func() time.Time { return time.Unix(1700000000, 0) },
		LockStatus: func(context.Context) (bool, error) {
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeClientSecret(b.cfg.SecretPath, clientSecret{ClientID: "cid", ClientSecret: "csecret"}); err != nil {
		t.Fatal(err)
	}

	if _, err := b.MintPhoneKey(context.Background(), "pair_dup"); err != nil {
		t.Fatalf("first mint failed: %v", err)
	}
	if _, err := b.MintPhoneKey(context.Background(), "pair_dup"); err == nil {
		t.Fatal("second mint succeeded, want duplicate rejection")
	}
	data, err := os.ReadFile(b.cfg.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"event":"duplicate_pair_id"`) || !strings.Contains(text, `"pair_id":"pair_dup"`) {
		t.Fatalf("audit missing duplicate_pair_id event: %s", text)
	}
	if strings.Contains(text, "tskey-auth-duplicate-secret") || strings.Contains(text, "authkey") {
		t.Fatalf("audit leaked key material: %s", text)
	}
}

func TestDuplicatePairIDWritesHealthAlert(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v2/tailnet/-/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "k-alert",
				"key":     "tskey-auth-alert-secret",
				"expires": time.Unix(1700000600, 0).Format(time.RFC3339),
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer api.Close()

	dir := t.TempDir()
	b, err := NewBroker(BrokerConfig{
		SecretPath: filepath.Join(dir, "client_secret.json"),
		StatePath:  filepath.Join(dir, "state.json"),
		AuditPath:  filepath.Join(dir, "audit.jsonl"),
		AlertPath:  filepath.Join(dir, "alerts.jsonl"),
		OAuthURL:   api.URL + "/oauth/token",
		APIBaseURL: api.URL + "/api/v2",
		Now:        func() time.Time { return time.Unix(1700000000, 0) },
		LockStatus: func(context.Context) (bool, error) {
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeClientSecret(b.cfg.SecretPath, clientSecret{ClientID: "cid", ClientSecret: "csecret"}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.MintPhoneKey(context.Background(), "pair_alert"); err != nil {
		t.Fatalf("first mint failed: %v", err)
	}
	if _, err := b.MintPhoneKey(context.Background(), "pair_alert"); err == nil {
		t.Fatal("second mint succeeded, want duplicate rejection")
	}

	data, err := os.ReadFile(b.cfg.AlertPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"event":"duplicate_pair_id"`) || !strings.Contains(text, `"pair_id":"pair_alert"`) {
		t.Fatalf("health alert missing duplicate_pair_id event: %s", text)
	}
	if strings.Contains(text, "tskey-auth-alert-secret") || strings.Contains(text, "authkey") {
		t.Fatalf("health alert leaked key material: %s", text)
	}
}

func TestMintRejectsMalformedPairIDBeforeAPI(t *testing.T) {
	apiCalls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls++
		t.Fatalf("malformed pair_id reached API path %s", r.URL.Path)
	}))
	defer api.Close()

	dir := t.TempDir()
	b, err := NewBroker(BrokerConfig{
		SecretPath: filepath.Join(dir, "client_secret.json"),
		StatePath:  filepath.Join(dir, "state.json"),
		AuditPath:  filepath.Join(dir, "audit.jsonl"),
		OAuthURL:   api.URL + "/oauth/token",
		APIBaseURL: api.URL + "/api/v2",
		Now:        func() time.Time { return time.Unix(1700000000, 0) },
		LockStatus: func(context.Context) (bool, error) {
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeClientSecret(b.cfg.SecretPath, clientSecret{ClientID: "cid", ClientSecret: "csecret"}); err != nil {
		t.Fatal(err)
	}

	if _, err := b.MintPhoneKey(context.Background(), "../../bad"); err == nil {
		t.Fatal("malformed pair_id minted, want validation error")
	}
	if apiCalls != 0 {
		t.Fatalf("apiCalls = %d, want 0", apiCalls)
	}
}

func TestMintRateLimited(t *testing.T) {
	keyPosts := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v2/tailnet/-/keys":
			keyPosts++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "k-test",
				"key":     "tskey-auth-test",
				"expires": time.Unix(1700000600, 0).Format(time.RFC3339),
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer api.Close()

	dir := t.TempDir()
	now := time.Unix(1700000000, 0)
	b, err := NewBroker(BrokerConfig{
		SecretPath: filepath.Join(dir, "client_secret.json"),
		StatePath:  filepath.Join(dir, "state.json"),
		AuditPath:  filepath.Join(dir, "audit.jsonl"),
		OAuthURL:   api.URL + "/oauth/token",
		APIBaseURL: api.URL + "/api/v2",
		Now:        func() time.Time { return now },
		LockStatus: func(context.Context) (bool, error) {
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeClientSecret(b.cfg.SecretPath, clientSecret{ClientID: "cid", ClientSecret: "csecret"}); err != nil {
		t.Fatal(err)
	}

	for _, pairID := range []string{"pair_1", "pair_2", "pair_3"} {
		if _, err := b.MintPhoneKey(context.Background(), pairID); err != nil {
			t.Fatalf("%s mint failed: %v", pairID, err)
		}
	}
	if _, err := b.MintPhoneKey(context.Background(), "pair_4"); err == nil {
		t.Fatal("fourth mint in 10 minutes succeeded, want rate limit")
	}
	if keyPosts != 3 {
		t.Fatalf("key mint POSTs = %d, want 3", keyPosts)
	}
}

func TestRateLimitAuditedWithoutKeyMaterial(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v2/tailnet/-/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "k-rate",
				"key":     "tskey-auth-rate-secret",
				"expires": time.Unix(1700000600, 0).Format(time.RFC3339),
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer api.Close()

	dir := t.TempDir()
	now := time.Unix(1700000000, 0)
	b, err := NewBroker(BrokerConfig{
		SecretPath: filepath.Join(dir, "client_secret.json"),
		StatePath:  filepath.Join(dir, "state.json"),
		AuditPath:  filepath.Join(dir, "audit.jsonl"),
		OAuthURL:   api.URL + "/oauth/token",
		APIBaseURL: api.URL + "/api/v2",
		Now:        func() time.Time { return now },
		LockStatus: func(context.Context) (bool, error) {
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeClientSecret(b.cfg.SecretPath, clientSecret{ClientID: "cid", ClientSecret: "csecret"}); err != nil {
		t.Fatal(err)
	}
	for _, pairID := range []string{"pair_rate_1", "pair_rate_2", "pair_rate_3"} {
		if _, err := b.MintPhoneKey(context.Background(), pairID); err != nil {
			t.Fatalf("%s mint failed: %v", pairID, err)
		}
	}
	if _, err := b.MintPhoneKey(context.Background(), "pair_rate_4"); err == nil {
		t.Fatal("fourth mint succeeded, want rate-limit rejection")
	}
	data, err := os.ReadFile(b.cfg.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"event":"mint_rate_limited"`) || !strings.Contains(text, `"pair_id":"pair_rate_4"`) {
		t.Fatalf("audit missing mint_rate_limited event: %s", text)
	}
	if strings.Contains(text, "tskey-auth-rate-secret") || strings.Contains(text, "authkey") {
		t.Fatalf("audit leaked key material: %s", text)
	}
}

func TestBrokerNeverRequestsDevicesCoreScope(t *testing.T) {
	var tokenScope string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = r.ParseForm()
			tokenScope = r.Form.Get("scope")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v2/tailnet/-/keys":
			if r.Method == http.MethodDelete {
				t.Fatal("broker attempted DeleteDevice/delete-key path")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "k-test",
				"key":     "tskey-auth-test",
				"expires": time.Unix(1700000600, 0).Format(time.RFC3339),
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer api.Close()

	dir := t.TempDir()
	b, err := NewBroker(BrokerConfig{
		SecretPath: filepath.Join(dir, "client_secret.json"),
		StatePath:  filepath.Join(dir, "state.json"),
		AuditPath:  filepath.Join(dir, "audit.jsonl"),
		OAuthURL:   api.URL + "/oauth/token",
		APIBaseURL: api.URL + "/api/v2",
		Now:        func() time.Time { return time.Unix(1700000000, 0) },
		LockStatus: func(context.Context) (bool, error) {
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeClientSecret(b.cfg.SecretPath, clientSecret{ClientID: "cid", ClientSecret: "csecret"}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.MintPhoneKey(context.Background(), "pair_abc123"); err != nil {
		t.Fatalf("MintPhoneKey failed: %v", err)
	}
	if tokenScope != "auth_keys" {
		t.Fatalf("token scope = %q, want auth_keys", tokenScope)
	}
	source, err := os.ReadFile("mintd.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"devices:core", "DeleteDevice"} {
		if bytes.Contains(source, []byte(forbidden)) {
			t.Fatalf("mintd.go contains forbidden credential/device scope %q", forbidden)
		}
	}
}

func TestBrokerAuditsKeyIdNotKey(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v2/tailnet/-/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "k-audit",
				"key":     "tskey-auth-secret-value",
				"expires": time.Unix(1700000600, 0).Format(time.RFC3339),
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer api.Close()

	dir := t.TempDir()
	b, err := NewBroker(BrokerConfig{
		SecretPath: filepath.Join(dir, "client_secret.json"),
		StatePath:  filepath.Join(dir, "state.json"),
		AuditPath:  filepath.Join(dir, "audit.jsonl"),
		OAuthURL:   api.URL + "/oauth/token",
		APIBaseURL: api.URL + "/api/v2",
		Now:        func() time.Time { return time.Unix(1700000000, 0) },
		LockStatus: func(context.Context) (bool, error) {
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeClientSecret(b.cfg.SecretPath, clientSecret{ClientID: "cid", ClientSecret: "csecret"}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.MintPhoneKey(context.Background(), "pair_audit"); err != nil {
		t.Fatalf("MintPhoneKey failed: %v", err)
	}

	data, err := os.ReadFile(b.cfg.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"key_id":"k-audit"`) || !strings.Contains(text, `"pair_id":"pair_audit"`) {
		t.Fatalf("audit record missing key_id/pair_id: %s", text)
	}
	if strings.Contains(text, "tskey-auth-secret-value") || strings.Contains(text, "authkey") {
		t.Fatalf("audit record leaked authkey: %s", text)
	}
}

func TestSocketRejectsMalformedRequest(t *testing.T) {
	apiCalls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls++
		t.Fatalf("malformed socket request reached API path %s", r.URL.Path)
	}))
	defer api.Close()

	dir := t.TempDir()
	b, err := NewBroker(BrokerConfig{
		SecretPath: filepath.Join(dir, "client_secret.json"),
		StatePath:  filepath.Join(dir, "state.json"),
		AuditPath:  filepath.Join(dir, "audit.jsonl"),
		OAuthURL:   api.URL + "/oauth/token",
		APIBaseURL: api.URL + "/api/v2",
		Now:        func() time.Time { return time.Unix(1700000000, 0) },
		LockStatus: func(context.Context) (bool, error) {
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("pairling-mintd-%d.sock", time.Now().UnixNano()))
	defer os.Remove(socketPath)
	errc := make(chan error, 1)
	go func() { errc <- b.ServeUnix(ctx, socketPath, os.Getuid()) }()
	waitForSocket(t, socketPath)

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(`{"op":"bad","pair_id":"pair_socket"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	var response map[string]any
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response["ok"] != false || response["error"] == nil {
		t.Fatalf("response = %#v, want ok:false with error", response)
	}
	if apiCalls != 0 {
		t.Fatalf("apiCalls = %d, want 0", apiCalls)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestServeUnixRequiresAuthorizedUID(t *testing.T) {
	b, err := NewBroker(BrokerConfig{
		Now: func() time.Time { return time.Unix(1700000000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	socketPath := filepath.Join("/tmp", fmt.Sprintf("pairling-mintd-noauth-%d.sock", time.Now().UnixNano()))
	defer os.Remove(socketPath)
	go func() {
		errc <- b.ServeUnix(ctx, socketPath, -1)
	}()
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "authorized uid required") {
			t.Fatalf("ServeUnix error = %v, want authorized uid required", err)
		}
	case <-time.After(100 * time.Millisecond):
		cancel()
		t.Fatal("ServeUnix opened socket with unset authorized uid")
	}
}

func TestHandleConnAuthorizesPeerUIDBeforeMint(t *testing.T) {
	cases := []struct {
		name        string
		uid         string
		peerErr     error
		wantOK      bool
		wantError   string
		wantAlert   string
		wantKeyPost int
	}{
		{
			name:        "wrong uid rejected before mint",
			uid:         "502",
			wantOK:      false,
			wantError:   "unauthorized_peer",
			wantAlert:   "unexpected_peer_uid",
			wantKeyPost: 0,
		},
		{
			name:        "authorized uid accepted",
			uid:         "501",
			wantOK:      true,
			wantKeyPost: 1,
		},
		{
			name:        "peercred error fail closed",
			peerErr:     errors.New("peercred boom"),
			wantOK:      false,
			wantError:   "peercred_unavailable",
			wantKeyPost: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyPosts := 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oauth/token":
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{
						"access_token": "test-token",
						"token_type":   "Bearer",
						"expires_in":   3600,
					})
				case "/api/v2/tailnet/-/keys":
					keyPosts++
					_ = json.NewEncoder(w).Encode(map[string]any{
						"id":      "k-peer",
						"key":     "tskey-auth-peer",
						"expires": time.Unix(1700000600, 0).Format(time.RFC3339),
					})
				default:
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
			}))
			defer api.Close()

			dir := t.TempDir()
			b, err := NewBroker(BrokerConfig{
				SecretPath: filepath.Join(dir, "client_secret.json"),
				StatePath:  filepath.Join(dir, "state.json"),
				AuditPath:  filepath.Join(dir, "audit.jsonl"),
				AlertPath:  filepath.Join(dir, "alerts.jsonl"),
				OAuthURL:   api.URL + "/oauth/token",
				APIBaseURL: api.URL + "/api/v2",
				Now:        func() time.Time { return time.Unix(1700000000, 0) },
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := writeClientSecret(b.cfg.SecretPath, clientSecret{ClientID: "cid", ClientSecret: "csecret"}); err != nil {
				t.Fatal(err)
			}

			oldPeerUID := peerUID
			peerUID = func(net.Conn) (string, error) {
				return tc.uid, tc.peerErr
			}
			defer func() { peerUID = oldPeerUID }()

			server, client := net.Pipe()
			defer client.Close()
			if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				b.handleConn(context.Background(), server, 501)
			}()
			if tc.peerErr == nil && tc.uid == "501" {
				_, _ = client.Write([]byte(`{"op":"mint_phone_key","pair_id":"pair_peer"}` + "\n"))
			}
			var response socketResponse
			if err := json.NewDecoder(client).Decode(&response); err != nil {
				t.Fatal(err)
			}
			<-done

			if response.OK != tc.wantOK {
				t.Fatalf("response OK = %v, want %v (response=%+v)", response.OK, tc.wantOK, response)
			}
			if tc.wantError != "" && response.Error != tc.wantError {
				t.Fatalf("response error = %q, want %q", response.Error, tc.wantError)
			}
			if keyPosts != tc.wantKeyPost {
				t.Fatalf("keyPosts = %d, want %d", keyPosts, tc.wantKeyPost)
			}
			alertBytes, _ := os.ReadFile(b.cfg.AlertPath)
			if tc.wantAlert != "" && !strings.Contains(string(alertBytes), tc.wantAlert) {
				t.Fatalf("alert %q missing from %s", tc.wantAlert, alertBytes)
			}
		})
	}
}

func TestOAuthTokenCachedInMemoryNotPersisted(t *testing.T) {
	tokenPosts := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenPosts++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "cached-test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v2/tailnet/-/keys":
			if got := r.Header.Get("Authorization"); got != "Bearer cached-test-token" {
				t.Fatalf("Authorization header = %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "k-test",
				"key":     "tskey-auth-test",
				"expires": time.Unix(1700000600, 0).Format(time.RFC3339),
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer api.Close()

	dir := t.TempDir()
	b, err := NewBroker(BrokerConfig{
		SecretPath: filepath.Join(dir, "client_secret.json"),
		StatePath:  filepath.Join(dir, "state.json"),
		AuditPath:  filepath.Join(dir, "audit.jsonl"),
		OAuthURL:   api.URL + "/oauth/token",
		APIBaseURL: api.URL + "/api/v2",
		Now:        func() time.Time { return time.Unix(1700000000, 0) },
		LockStatus: func(context.Context) (bool, error) {
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeClientSecret(b.cfg.SecretPath, clientSecret{ClientID: "cid", ClientSecret: "csecret"}); err != nil {
		t.Fatal(err)
	}
	for _, pairID := range []string{"pair_cache_1", "pair_cache_2"} {
		if _, err := b.MintPhoneKey(context.Background(), pairID); err != nil {
			t.Fatalf("%s mint failed: %v", pairID, err)
		}
	}
	if tokenPosts != 1 {
		t.Fatalf("OAuth token POSTs = %d, want 1", tokenPosts)
	}
	for _, path := range []string{b.cfg.StatePath, b.cfg.AuditPath} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("cached-test-token")) {
			t.Fatalf("%s persisted OAuth access token", path)
		}
	}
}

func TestMintLockAwareSignDeferred(t *testing.T) {
	apiCalls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls++
		switch r.URL.Path {
		case "/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v2/tailnet/-/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "k-lock",
				"key":     "tskey-auth-lock",
				"expires": time.Unix(1700000600, 0).Format(time.RFC3339),
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer api.Close()

	dir := t.TempDir()
	b, err := NewBroker(BrokerConfig{
		SecretPath: filepath.Join(dir, "client_secret.json"),
		StatePath:  filepath.Join(dir, "state.json"),
		AuditPath:  filepath.Join(dir, "audit.jsonl"),
		OAuthURL:   api.URL + "/oauth/token",
		APIBaseURL: api.URL + "/api/v2",
		Now:        func() time.Time { return time.Unix(1700000000, 0) },
		LockStatus: func(context.Context) (bool, error) {
			return true, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeClientSecret(b.cfg.SecretPath, clientSecret{ClientID: "cid", ClientSecret: "csecret"}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.MintPhoneKey(context.Background(), "pair_lock"); err == nil {
		t.Fatal("mint succeeded while tailnet lock enabled")
	}
	if apiCalls != 0 {
		t.Fatalf("apiCalls = %d, want 0 when lock is enabled", apiCalls)
	}
}

func TestLockStatusFallsBackPastGUIWrapper(t *testing.T) {
	dir := t.TempDir()
	guiWrapper := filepath.Join(dir, "tailscale-gui")
	cli := filepath.Join(dir, "tailscale-cli")
	if err := os.WriteFile(guiWrapper, []byte("#!/bin/sh\necho 'The Tailscale GUI failed to start: test GUI unavailable'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cli, []byte("#!/bin/sh\necho 'Tailnet Lock is NOT enabled.'\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	locked, err := lockStatusFromCandidates(context.Background(), []string{guiWrapper, cli})
	if err != nil {
		t.Fatalf("lockStatusFromCandidates failed: %v", err)
	}
	if locked {
		t.Fatal("lock status reported enabled after non-GUI CLI said NOT enabled")
	}
}

func TestLockStatusUsesConnectdStatusBeforeCLI(t *testing.T) {
	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"tailnet_lock_enabled": false})
	}))
	defer status.Close()

	locked, err := lockStatusFromConnectdStatus(context.Background(), status.URL)
	if err != nil {
		t.Fatalf("lockStatusFromConnectdStatus failed: %v", err)
	}
	if locked {
		t.Fatal("lock status reported enabled")
	}
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket did not appear: %s", path)
}
