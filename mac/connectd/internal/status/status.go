package status

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	SchemaVersion          = 2
	DefaultListenPort      = 7773
	DefaultConnectdVersion = "2026-05-24"
	DefaultControlURLMode  = "tailscale_saas"
	CustomControlURLMode   = "custom"
	RouteIDPairlingConnect = "pairling-connect-tailnet"
	RouteSourceConnectd    = "pairling_connectd"
	RouteKindTailnet       = "tailnet"
	RouteKindFunnel        = "funnel"
	RouteStatusReady       = "ready"
	RouteIDFunnel          = "pairling-connect-funnel"
)

type AdvertisedRoute struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Source   string `json:"source"`
	Priority int    `json:"priority"`
	BaseURL  string `json:"base_url"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Status   string `json:"status"`
}

type Snapshot struct {
	OK                   bool              `json:"ok"`
	SchemaVersion        int               `json:"schema_version"`
	AuthState            string            `json:"auth_state"`
	Hostname             string            `json:"hostname"`
	FunnelHostname       string            `json:"funnel_hostname,omitempty"`
	TailnetIP            string            `json:"tailnet_ip,omitempty"`
	TailnetNodeID        string            `json:"tailnet_node_id,omitempty"`
	Tags                 []string          `json:"tags,omitempty"`
	TailnetIPs           []string          `json:"tailnet_ips,omitempty"`
	TailnetLockEnabled   *bool             `json:"tailnet_lock_enabled,omitempty"`
	TailnetIPCount       int               `json:"tailnet_ip_count"`
	AuthURLPresent       bool              `json:"auth_url_present"`
	ControlURLMode       string            `json:"control_url_mode"`
	AuthKeyMode          string            `json:"auth_key_mode,omitempty"`
	UpstreamReachable    bool              `json:"upstream_reachable"`
	ListenerRunning      bool              `json:"listener_running"`
	GatewayHealthy       bool              `json:"gateway_healthy"`
	ListenPort           int               `json:"listen_port"`
	ConnectdVersion      string            `json:"connectd_version"`
	AdvertisedRoutes     []AdvertisedRoute `json:"advertised_routes"`
	LastError            string            `json:"last_error,omitempty"`
	LastGatewayFailure   string            `json:"last_gateway_failure,omitempty"`
	LastGatewayFailureAt string            `json:"last_gateway_failure_at,omitempty"`
	UpdatedAt            string            `json:"updated_at"`
}

type Store struct {
	mu                   sync.RWMutex
	snapshot             Snapshot
	authURL              string
	gatewaySuccessStreak int
}

func NewStore(hostname string) *Store {
	return &Store{
		snapshot: Snapshot{
			OK:               true,
			SchemaVersion:    SchemaVersion,
			AuthState:        "starting",
			Hostname:         hostname,
			ControlURLMode:   DefaultControlURLMode,
			GatewayHealthy:   true,
			ListenPort:       DefaultListenPort,
			ConnectdVersion:  DefaultConnectdVersion,
			AdvertisedRoutes: []AdvertisedRoute{},
			UpdatedAt:        nowString(),
		},
	}
}

func (s *Store) SetControlURLMode(mode string) {
	s.update(func(snapshot *Snapshot) {
		if mode == "" {
			mode = DefaultControlURLMode
		}
		snapshot.ControlURLMode = mode
	})
}

// SetAuthKeyMode records how this node authenticated: "tagged" (a tagged
// auth key, key expiry disabled) or "interactive" (the legacy browser flow).
func (s *Store) SetAuthKeyMode(mode string) {
	s.update(func(snapshot *Snapshot) {
		snapshot.AuthKeyMode = mode
	})
}

func (s *Store) SetListenPort(port int) {
	s.update(func(snapshot *Snapshot) {
		if port <= 0 {
			port = DefaultListenPort
		}
		snapshot.ListenPort = port
	})
}

func (s *Store) SetConnectdVersion(version string) {
	s.update(func(snapshot *Snapshot) {
		if version == "" {
			version = DefaultConnectdVersion
		}
		snapshot.ConnectdVersion = version
	})
}

// SetFunnelHostname records the public *.ts.net hostname of the Funnel listener.
// Empty when Funnel is disabled, which keeps the snapshot and advertised routes
// byte-identical to the no-funnel build.
func (s *Store) SetFunnelHostname(host string) {
	s.update(func(snapshot *Snapshot) {
		snapshot.FunnelHostname = strings.TrimSpace(host)
	})
}

func (s *Store) SetAuthPending(message string) {
	s.update(func(snapshot *Snapshot) {
		snapshot.AuthState = "pending"
		if authURL, ok := extractAuthURL(message); ok {
			s.authURL = authURL
			snapshot.AuthURLPresent = true
		}
	})
}

func (s *Store) SetAuthenticated() {
	s.update(func(snapshot *Snapshot) {
		snapshot.AuthState = "authenticated"
		s.authURL = ""
		snapshot.AuthURLPresent = false
	})
}

func (s *Store) SetTailnetIP(ip string) {
	s.update(func(snapshot *Snapshot) {
		snapshot.TailnetIP = ip
		if ip == "" {
			snapshot.TailnetIPCount = 0
		} else {
			snapshot.TailnetIPCount = 1
		}
	})
}

func (s *Store) SetTailnetIdentity(nodeID string, tags, ips []string) {
	s.update(func(snapshot *Snapshot) {
		snapshot.TailnetNodeID = sanitizeIdentityValue(nodeID)
		snapshot.Tags = sanitizeIdentityValues(tags)
		snapshot.TailnetIPs = sanitizeIdentityValues(ips)
	})
}

func (s *Store) SetTailnetLockEnabled(enabled bool) {
	s.update(func(snapshot *Snapshot) {
		snapshot.TailnetLockEnabled = &enabled
	})
}

func (s *Store) SetUpstreamReachable(reachable bool) {
	s.update(func(snapshot *Snapshot) {
		snapshot.UpstreamReachable = reachable
	})
}

func (s *Store) SetListenerRunning(running bool) {
	s.update(func(snapshot *Snapshot) {
		snapshot.ListenerRunning = running
	})
}

func (s *Store) RecordGatewayEvent(method, path string, status int, outcome string) {
	s.update(func(snapshot *Snapshot) {
		method = strings.ToUpper(strings.TrimSpace(method))
		path = strings.TrimSpace(path)
		outcome = strings.TrimSpace(outcome)
		if gatewayEventIsFailure(path, status, outcome) {
			s.gatewaySuccessStreak = 0
			snapshot.GatewayHealthy = false
			snapshot.LastGatewayFailure = redact(fmt.Sprintf("%s %s status=%d outcome=%s", method, path, status, outcome))
			snapshot.LastGatewayFailureAt = nowString()
			return
		}
		if gatewayEventIsRecoveryProbe(path, status, outcome) {
			s.gatewaySuccessStreak = 1
			snapshot.GatewayHealthy = true
			snapshot.LastGatewayFailure = ""
			snapshot.LastGatewayFailureAt = ""
			return
		}
	})
}

func (s *Store) SetLastError(message string) {
	s.update(func(snapshot *Snapshot) {
		snapshot.LastError = redact(message)
		if message != "" {
			snapshot.OK = false
		}
	})
}

func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshot
}

func (s *Store) AuthURLForOpen() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.authURL == "" || !s.snapshot.AuthURLPresent {
		return "", false
	}
	return validateAuthURL(s.authURL)
}

func (s *Store) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.Snapshot())
	})
}

func (s *Store) update(fn func(*Snapshot)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.snapshot)
	s.snapshot.AdvertisedRoutes = advertisedRoutes(s.snapshot)
	s.snapshot.UpdatedAt = nowString()
}

func advertisedRoutes(snapshot Snapshot) []AdvertisedRoute {
	if snapshot.AuthState != "authenticated" || snapshot.TailnetIP == "" || !snapshot.ListenerRunning || !snapshot.UpstreamReachable || !snapshot.GatewayHealthy {
		return []AdvertisedRoute{}
	}
	port := snapshot.ListenPort
	if port <= 0 {
		port = DefaultListenPort
	}
	routes := []AdvertisedRoute{{
		ID:       RouteIDPairlingConnect,
		Kind:     RouteKindTailnet,
		Source:   RouteSourceConnectd,
		Priority: 100,
		BaseURL:  fmt.Sprintf("http://%s:%d", snapshot.TailnetIP, port),
		Host:     snapshot.TailnetIP,
		Port:     port,
		Status:   RouteStatusReady,
	}}
	// Additive funnel route, lowest priority so it is used only for the off-LAN
	// bootstrap and dropped once the tailnet route is reachable. Present only when
	// Funnel is enabled (a hostname is set); the health gate above already holds.
	if host := strings.TrimSpace(snapshot.FunnelHostname); host != "" {
		routes = append(routes, AdvertisedRoute{
			ID:       RouteIDFunnel,
			Kind:     RouteKindFunnel,
			Source:   RouteSourceConnectd,
			Priority: 10,
			BaseURL:  "https://" + host,
			Host:     host,
			Port:     443,
			Status:   RouteStatusReady,
		})
	}
	return routes
}

func gatewayEventIsFailure(path string, status int, outcome string) bool {
	path = strings.TrimSpace(path)
	if path != "/routez" {
		return false
	}
	outcome = strings.ToLower(strings.TrimSpace(outcome))
	if outcome == "upstream_error" || outcome == "validation_failed" || outcome == "timeout" {
		return true
	}
	if status >= 500 {
		return true
	}
	return false
}

func gatewayEventIsRecoveryProbe(path string, status int, outcome string) bool {
	outcome = strings.ToLower(strings.TrimSpace(outcome))
	return path == "/routez" && outcome == "forwarded" && status >= 200 && status < 400
}

func nowString() string {
	return time.Now().UTC().Format(time.RFC3339)
}

var secretPattern = regexp.MustCompile(`(?i)(sk-[A-Za-z0-9._-]+|[A-Za-z0-9._-]*secret[A-Za-z0-9._-]*|[A-Za-z0-9._-]*token[A-Za-z0-9._-]*)`)
var authURLPattern = regexp.MustCompile(`https://login\.tailscale\.com/a/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]+`)
var bearerPattern = regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/=-]+`)
var tailscaleAuthKeyPattern = regexp.MustCompile(`(?i)tskey-[A-Za-z0-9._-]+`)
var identitySecretPattern = regexp.MustCompile(`(?i)(authkey|nlprivate)`)

func sanitizeIdentityValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		cleaned = append(cleaned, sanitizeIdentityValue(value))
	}
	return cleaned
}

func sanitizeIdentityValue(value string) string {
	value = strings.TrimSpace(value)
	if identitySecretPattern.MatchString(value) {
		return "[redacted]"
	}
	return redact(value)
}

func extractAuthURL(value string) (string, bool) {
	raw := authURLPattern.FindString(value)
	if raw == "" {
		return "", false
	}
	return validateAuthURL(raw)
}

func ValidAuthURL(value string) bool {
	_, ok := validateAuthURL(value)
	return ok
}

func validateAuthURL(raw string) (string, bool) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if parsed.Scheme != "https" || strings.ToLower(parsed.Host) != "login.tailscale.com" {
		return "", false
	}
	if parsed.User != nil || parsed.Fragment != "" || !strings.HasPrefix(parsed.Path, "/a/") || len(parsed.Path) <= len("/a/") {
		return "", false
	}
	return raw, true
}

func redact(value string) string {
	value = authURLPattern.ReplaceAllString(value, "https://login.tailscale.com/a/[redacted]")
	value = bearerPattern.ReplaceAllString(value, "Bearer [redacted]")
	value = tailscaleAuthKeyPattern.ReplaceAllString(value, "[redacted]")
	return secretPattern.ReplaceAllString(value, "[redacted]")
}

func Redact(value string) string {
	return redact(value)
}
