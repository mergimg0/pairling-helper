package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/tailscale/peercred"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const phoneTag = "tag:pairling-phone"

var pairIDPattern = regexp.MustCompile(`^pair_[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

var peerUID = func(conn net.Conn) (string, error) {
	creds, err := peercred.Get(conn)
	if err != nil {
		return "", err
	}
	uid, ok := creds.UserID()
	if !ok {
		return "", fmt.Errorf("peer uid unavailable")
	}
	return uid, nil
}

type BrokerConfig struct {
	SecretPath string
	StatePath  string
	AuditPath  string
	AlertPath  string
	OAuthURL   string
	APIBaseURL string
	Now        func() time.Time
	LockStatus func(context.Context) (bool, error)
	HTTPClient *http.Client
}

type Broker struct {
	cfg         BrokerConfig
	mu          sync.Mutex
	tokenSource oauth2.TokenSource
}

type clientSecret struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes,omitempty"`
	Tags         []string `json:"tags,omitempty"`
}

type MintResult struct {
	AuthKey   string `json:"authkey"`
	KeyID     string `json:"key_id"`
	ExpiresAt int64  `json:"expires_at"`
}

type socketRequest struct {
	Op     string `json:"op"`
	PairID string `json:"pair_id"`
}

type socketResponse struct {
	OK        bool   `json:"ok"`
	AuthKey   string `json:"authkey,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

type brokerState struct {
	SuccessfulPairs map[string]int64 `json:"successful_pairs,omitempty"`
	SuccessfulMints []int64          `json:"successful_mints,omitempty"`
}

func NewBroker(cfg BrokerConfig) (*Broker, error) {
	if cfg.OAuthURL == "" {
		cfg.OAuthURL = "https://api.tailscale.com/api/v2/oauth/token"
	}
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = "https://api.tailscale.com/api/v2"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	return &Broker{cfg: cfg}, nil
}

func writeClientSecret(path string, secret clientSecret) error {
	data, err := json.MarshalIndent(secret, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func readClientSecret(path string) (clientSecret, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return clientSecret{}, err
	}
	var secret clientSecret
	if err := json.Unmarshal(data, &secret); err != nil {
		return clientSecret{}, err
	}
	if secret.ClientID == "" || secret.ClientSecret == "" {
		return clientSecret{}, fmt.Errorf("missing client_id or client_secret")
	}
	return secret, nil
}

func (b *Broker) MintPhoneKey(ctx context.Context, pairID string) (MintResult, error) {
	if !pairIDPattern.MatchString(pairID) {
		return MintResult{}, fmt.Errorf("invalid pair_id")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	state, err := b.loadState()
	if err != nil {
		return MintResult{}, err
	}
	now := b.cfg.Now().Unix()
	if state.SuccessfulPairs[pairID] != 0 {
		_ = b.alert(map[string]any{
			"event":   "duplicate_pair_id",
			"ts":      now,
			"pair_id": pairID,
		})
		return MintResult{}, fmt.Errorf("pair_id already minted")
	}
	state.SuccessfulMints = pruneSince(state.SuccessfulMints, now-24*60*60)
	if countSince(state.SuccessfulMints, now-10*60) >= 3 {
		_ = b.alert(map[string]any{
			"event":   "mint_rate_limited",
			"ts":      now,
			"pair_id": pairID,
			"window":  "10m",
		})
		return MintResult{}, fmt.Errorf("mint rate limited")
	}
	if len(state.SuccessfulMints) >= 12 {
		_ = b.alert(map[string]any{
			"event":   "mint_rate_limited",
			"ts":      now,
			"pair_id": pairID,
			"window":  "24h",
		})
		return MintResult{}, fmt.Errorf("mint rate limited")
	}
	locked, err := b.lockEnabled(ctx)
	if err != nil {
		return MintResult{}, err
	}
	if locked {
		return MintResult{}, fmt.Errorf("tailnet lock enabled; unsigned minting is disabled")
	}
	secret, err := readClientSecret(b.cfg.SecretPath)
	if err != nil {
		return MintResult{}, err
	}
	token, err := b.token(ctx, secret)
	if err != nil {
		return MintResult{}, err
	}
	body := map[string]any{
		"capabilities": map[string]any{
			"devices": map[string]any{
				"create": map[string]any{
					"reusable":      false,
					"ephemeral":     false,
					"preauthorized": true,
					"tags":          []string{phoneTag},
				},
			},
		},
		"expirySeconds": 600,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return MintResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.cfg.APIBaseURL+"/tailnet/-/keys", bytes.NewReader(payload))
	if err != nil {
		return MintResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.cfg.HTTPClient.Do(req)
	if err != nil {
		return MintResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return MintResult{}, fmt.Errorf("tailscale key mint failed: %s", resp.Status)
	}
	var out struct {
		ID      string `json:"id"`
		Key     string `json:"key"`
		Expires string `json:"expires"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return MintResult{}, err
	}
	exp, _ := time.Parse(time.RFC3339, out.Expires)
	result := MintResult{AuthKey: out.Key, KeyID: out.ID, ExpiresAt: exp.Unix()}
	state.SuccessfulPairs[pairID] = now
	state.SuccessfulMints = append(state.SuccessfulMints, now)
	if err := b.saveState(state); err != nil {
		return MintResult{}, err
	}
	if err := b.audit(map[string]any{
		"event":   "mint_success",
		"ts":      now,
		"pair_id": pairID,
		"key_id":  out.ID,
	}); err != nil {
		return MintResult{}, err
	}
	return result, nil
}

func pruneSince(times []int64, cutoff int64) []int64 {
	kept := times[:0]
	for _, ts := range times {
		if ts >= cutoff {
			kept = append(kept, ts)
		}
	}
	return kept
}

func countSince(times []int64, cutoff int64) int {
	count := 0
	for _, ts := range times {
		if ts >= cutoff {
			count++
		}
	}
	return count
}

func (b *Broker) token(ctx context.Context, secret clientSecret) (*oauth2.Token, error) {
	if b.tokenSource == nil {
		oauth := clientcredentials.Config{
			ClientID:     secret.ClientID,
			ClientSecret: secret.ClientSecret,
			TokenURL:     b.cfg.OAuthURL,
			Scopes:       []string{"auth_keys"},
		}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, b.cfg.HTTPClient)
		b.tokenSource = oauth2.ReuseTokenSource(nil, oauth.TokenSource(ctx))
	}
	return b.tokenSource.Token()
}

func (b *Broker) lockEnabled(ctx context.Context) (bool, error) {
	if b.cfg.LockStatus == nil {
		return false, nil
	}
	return b.cfg.LockStatus(ctx)
}

func (b *Broker) ServeUnix(ctx context.Context, socketPath string, authorizedUID int) error {
	if authorizedUID < 0 {
		return fmt.Errorf("authorized uid required")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o750); err != nil {
		return err
	}
	_ = os.Remove(socketPath)
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = l.Close()
		_ = os.Remove(socketPath)
	}()
	_ = os.Chmod(socketPath, 0o660)
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go b.handleConn(ctx, conn, authorizedUID)
	}
}

func (b *Broker) handleConn(ctx context.Context, conn net.Conn, authorizedUID int) {
	defer conn.Close()
	uid, err := peerUID(conn)
	if err != nil {
		_ = json.NewEncoder(conn).Encode(socketResponse{OK: false, Error: "peercred_unavailable"})
		return
	}
	if err := authorizePeer(uid, authorizedUID); err != nil {
		_ = b.alert(map[string]any{"event": "unexpected_peer_uid", "ts": b.cfg.Now().Unix(), "uid": uid})
		_ = json.NewEncoder(conn).Encode(socketResponse{OK: false, Error: "unauthorized_peer"})
		return
	}
	var req socketRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(socketResponse{OK: false, Error: "bad_json"})
		return
	}
	if req.Op != "mint_phone_key" || req.PairID == "" {
		_ = json.NewEncoder(conn).Encode(socketResponse{OK: false, Error: "bad_request"})
		return
	}
	res, err := b.MintPhoneKey(ctx, req.PairID)
	if err != nil {
		_ = json.NewEncoder(conn).Encode(socketResponse{OK: false, Error: err.Error()})
		return
	}
	_ = json.NewEncoder(conn).Encode(socketResponse{
		OK:        true,
		AuthKey:   res.AuthKey,
		KeyID:     res.KeyID,
		ExpiresAt: res.ExpiresAt,
	})
}

func authorizePeer(uid string, authorizedUID int) error {
	if uid != strconv.Itoa(authorizedUID) {
		return fmt.Errorf("unexpected peer uid")
	}
	return nil
}

func (b *Broker) loadState() (brokerState, error) {
	state := brokerState{SuccessfulPairs: map[string]int64{}}
	if b.cfg.StatePath == "" {
		return state, nil
	}
	data, err := os.ReadFile(b.cfg.StatePath)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	if state.SuccessfulPairs == nil {
		state.SuccessfulPairs = map[string]int64{}
	}
	return state, nil
}

func (b *Broker) saveState(state brokerState) error {
	if b.cfg.StatePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(b.cfg.StatePath), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(b.cfg.StatePath, data, 0o600)
}

func (b *Broker) audit(record map[string]any) error {
	return appendJSONL(b.cfg.AuditPath, record, 0o700, 0o600)
}

func (b *Broker) alert(record map[string]any) error {
	if err := b.audit(record); err != nil {
		return err
	}
	return appendJSONL(b.cfg.AlertPath, record, 0o750, 0o640)
}

func appendJSONL(path string, record map[string]any, dirMode, fileMode os.FileMode) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
