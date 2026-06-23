package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

const defaultMaxBodyBytes int64 = 1_000_000
const prePairMaxBodyBytes int64 = 16 * 1024
const pairDropSmallFileMaxBodyBytes int64 = 10 * 1024 * 1024
const pairDropUploadChunkMaxBodyBytes int64 = 1024 * 1024
const peerNodeHeader = "X-Pairling-Peer-Node"

// funnelOriginHeader marks a request that arrived over the public Funnel
// listener. connectd sets it only on the funnel handler and deletes any inbound
// copy first; every other handler deletes it, so a client can never forge it.
const funnelOriginHeader = "X-Pairling-Funnel-Origin"

// Chat attachment uploads (POST /upload) carry whole photos/short videos in
// one shot — the 1MB default rejected most camera photos with 413.
const chatUploadMaxBodyBytes int64 = 25 * 1024 * 1024

type ExposureMode string

const (
	ExposureModePostPair        ExposureMode = "post_pair"
	ExposureModePrePair         ExposureMode = "pre_pair"
	ExposureModePairlingConnect ExposureMode = "pairling_connect"
	// ExposureModeFunnelBootstrap is the public Funnel surface. It is the most
	// restrictive mode: only the minimal bootstrap claim plus health probes, with
	// no bearer post-pair fallthrough. Used only by the separate ListenFunnel
	// handler, never by the tailnet listener.
	ExposureModeFunnelBootstrap ExposureMode = "funnel_bootstrap"
)

// Logger receives metadata-only gateway events. Event intentionally excludes
// request bodies, query values, authorization values, and proof material.
type Logger interface {
	Log(Event)
}

type PeerNodeResolver interface {
	PeerNodeID(ctx context.Context, remoteAddr string) (string, bool)
}

type Event struct {
	Method  string
	Path    string
	Outcome string
	Status  int
}

type Options struct {
	Upstream         *url.URL
	MaxBodyBytes     int64
	Mode             ExposureMode
	Logger           Logger
	RateLimiter      RateLimiter
	PeerNodeResolver PeerNodeResolver
	// FunnelMacIDHash, when set, is returned in the synthesized funnel-mode
	// /health and /manifest responses so a phone can confirm it reached the Mac
	// named in its QR, without the upstream's identity fields ever being exposed.
	FunnelMacIDHash string
	// FunnelLimiter, when set, owns identity-independent rate limiting on the
	// funnel claim path. Used instead of RateLimiter for the funnel handler.
	FunnelLimiter *FunnelLimiter
}

type Handler struct {
	upstream         *url.URL
	maxBodyBytes     int64
	mode             ExposureMode
	logger           Logger
	rateLimiter      RateLimiter
	peerNodeResolver PeerNodeResolver
	funnelMacIDHash  string
	funnelLimiter    *FunnelLimiter
	proxy            *httputil.ReverseProxy
}

type RateLimiter interface {
	Allow(remoteAddr, method, path string) bool
}

func NewHandler(opts Options) (*Handler, error) {
	if opts.Upstream == nil {
		return nil, errors.New("upstream is required")
	}
	if opts.Upstream.Scheme != "http" && opts.Upstream.Scheme != "https" {
		return nil, errors.New("upstream scheme must be http or https")
	}
	if opts.Upstream.Host == "" {
		return nil, errors.New("upstream host is required")
	}
	if !localUpstream(opts.Upstream) {
		return nil, errors.New("upstream host must be loopback")
	}
	maxBody := opts.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = defaultMaxBodyBytes
	}
	mode := opts.Mode
	if mode == "" {
		mode = ExposureModePostPair
	}
	if mode != ExposureModePostPair && mode != ExposureModePrePair && mode != ExposureModePairlingConnect && mode != ExposureModeFunnelBootstrap {
		return nil, errors.New("unknown exposure mode")
	}
	upstream := *opts.Upstream
	h := &Handler{
		upstream:         &upstream,
		maxBodyBytes:     maxBody,
		mode:             mode,
		logger:           opts.Logger,
		rateLimiter:      opts.RateLimiter,
		peerNodeResolver: opts.PeerNodeResolver,
		funnelMacIDHash:  opts.FunnelMacIDHash,
		funnelLimiter:    opts.FunnelLimiter,
	}
	h.proxy = &httputil.ReverseProxy{
		Rewrite:       h.rewrite,
		ErrorHandler:  h.proxyError,
		FlushInterval: -1,
	}
	return h, nil
}

// isFunnelSynthesizedPath reports the funnel-mode GET paths connectd answers
// itself with a minimal body, so the upstream's identity, version, install
// path, and route topology never reach the public surface. /healthz shares the
// sensitive /health payload upstream, so it is synthesized too. /readyz is left
// to proxy because it is the warmup readiness probe and carries no identity.
func isFunnelSynthesizedPath(path string) bool {
	return path == "/health" || path == "/healthz" || path == "/manifest"
}

func (h *Handler) writeFunnelHealth(w http.ResponseWriter, r *http.Request, path string) {
	body := map[string]any{"ok": true}
	if (path == "/health" || path == "/manifest") && h.funnelMacIDHash != "" {
		body["mac_id_hash"] = h.funnelMacIDHash
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
	h.log(r, http.StatusOK, "funnel_synthesized")
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if !supportedMethod(r.Method) {
		h.reject(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if !h.allowed(r.Method, path, r.Header) {
		if h.allowedForAnyMethod(path, r.Header) {
			h.reject(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		h.reject(w, r, http.StatusNotFound, "path_not_allowed")
		return
	}
	if h.mode == ExposureModeFunnelBootstrap && r.Method == http.MethodGet && isFunnelSynthesizedPath(path) {
		h.writeFunnelHealth(w, r, path)
		return
	}
	if h.funnelLimiter != nil && h.mode == ExposureModeFunnelBootstrap && r.Method == http.MethodPost && isPrePairClaimPath(path) {
		body, err := io.ReadAll(io.LimitReader(r.Body, prePairMaxBodyBytes+1))
		if err != nil || int64(len(body)) > prePairMaxBodyBytes {
			h.reject(w, r, http.StatusRequestEntityTooLarge, "request_too_large")
			return
		}
		release, ok := h.funnelLimiter.Acquire(extractPairID(body))
		if !ok {
			h.reject(w, r, http.StatusTooManyRequests, "rate_limited")
			return
		}
		defer release()
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}
	if h.rateLimiter != nil && h.rateLimitPath(r.Method, path) && !h.rateLimiter.Allow(r.RemoteAddr, r.Method, path) {
		h.reject(w, r, http.StatusTooManyRequests, "rate_limited")
		return
	}
	bodyLimit := h.requestBodyLimit(r.Method, path)
	if bodyLimit > 0 {
		if r.ContentLength > bodyLimit {
			h.reject(w, r, http.StatusRequestEntityTooLarge, "request_too_large")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, bodyLimit)
	}

	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	h.proxy.ServeHTTP(rec, r)
	h.log(r, rec.status, "forwarded")
}

func (h *Handler) rewrite(r *httputil.ProxyRequest) {
	in := r.In
	r.SetURL(h.upstream)
	r.Out.URL.Path = joinPath(h.upstream.Path, in.URL.Path)
	r.Out.URL.RawPath = ""
	if h.upstream.RawQuery == "" || in.URL.RawQuery == "" {
		r.Out.URL.RawQuery = h.upstream.RawQuery + in.URL.RawQuery
	} else {
		r.Out.URL.RawQuery = h.upstream.RawQuery + "&" + in.URL.RawQuery
	}
	r.Out.Host = h.upstream.Host
	r.Out.Header.Del("X-Forwarded-For")
	r.Out.Header.Del(peerNodeHeader)
	r.Out.Header.Del(funnelOriginHeader)
	if h.mode == ExposureModeFunnelBootstrap {
		r.Out.Header.Set(funnelOriginHeader, "1")
	}
	if h.peerNodeResolver != nil {
		if nodeID, ok := h.peerNodeResolver.PeerNodeID(in.Context(), in.RemoteAddr); ok {
			if nodeID = strings.TrimSpace(nodeID); nodeID != "" {
				r.Out.Header.Set(peerNodeHeader, nodeID)
			}
		}
	}
	r.Out.Header.Set("X-Pairling-Connect-Gateway", "pairling-connectd")
	r.SetXForwarded()
}

// FunnelLimiter owns identity-independent rate limiting for the public Funnel
// claim path. The real client IP is unrecoverable over tsnet.ListenFunnel, so
// none of these limits depend on it: a global per-minute ceiling (a circuit
// breaker), a per-pair_id cap (matching the 5-attempt lockout, so a victim whose
// pair_id is unknown to an attacker is unaffected), and an in-flight ECDH
// concurrency cap (so a pair_id spray cannot force unbounded P-256/HKDF work).
type FunnelLimiter struct {
	mu           sync.Mutex
	now          func() time.Time
	window       time.Duration
	globalLimit  int
	perPairLimit int
	globalHits   []time.Time
	perPair      map[string][]time.Time
	ecdhSem      chan struct{}
}

func NewFunnelLimiter(globalPerMinute, perPairMax, ecdhConcurrency int) *FunnelLimiter {
	if globalPerMinute <= 0 {
		globalPerMinute = 120
	}
	if perPairMax <= 0 {
		perPairMax = 5
	}
	if ecdhConcurrency <= 0 {
		ecdhConcurrency = 6
	}
	return &FunnelLimiter{
		now:          time.Now,
		window:       time.Minute,
		globalLimit:  globalPerMinute,
		perPairLimit: perPairMax,
		perPair:      map[string][]time.Time{},
		ecdhSem:      make(chan struct{}, ecdhConcurrency),
	}
}

// Acquire enforces the three caps and acquires an ECDH slot. It returns a
// release func that frees the slot when the claim finishes. ok is false when any
// budget is exhausted, in which case nothing is held.
func (l *FunnelLimiter) Acquire(pairID string) (release func(), ok bool) {
	if l == nil {
		return func() {}, true
	}
	select {
	case l.ecdhSem <- struct{}{}:
	default:
		return nil, false
	}
	l.mu.Lock()
	now := l.now()
	cutoff := now.Add(-l.window)
	l.globalHits = pruneTimes(l.globalHits, cutoff)
	ph := pruneTimes(l.perPair[pairID], cutoff)
	if len(l.globalHits) >= l.globalLimit || len(ph) >= l.perPairLimit {
		l.perPair[pairID] = ph
		l.mu.Unlock()
		<-l.ecdhSem
		return nil, false
	}
	l.globalHits = append(l.globalHits, now)
	l.perPair[pairID] = append(ph, now)
	if len(l.perPair) > 4096 {
		for k, v := range l.perPair {
			stale := true
			for _, t := range v {
				if t.After(cutoff) {
					stale = false
					break
				}
			}
			if stale {
				delete(l.perPair, k)
			}
		}
	}
	l.mu.Unlock()
	return func() { <-l.ecdhSem }, true
}

func pruneTimes(times []time.Time, cutoff time.Time) []time.Time {
	kept := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	return kept
}

func extractPairID(body []byte) string {
	var obj struct {
		PairID string `json:"pair_id"`
	}
	if json.Unmarshal(body, &obj) != nil {
		return ""
	}
	return obj.PairID
}

func (h *Handler) proxyError(w http.ResponseWriter, r *http.Request, err error) {
	h.reject(w, r, http.StatusBadGateway, "upstream_error")
}

func (h *Handler) reject(w http.ResponseWriter, r *http.Request, status int, code string) {
	h.log(r, status, code)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": false,
		"error": map[string]string{
			"code": code,
		},
	})
}

func (h *Handler) log(r *http.Request, status int, outcome string) {
	if h.logger == nil {
		return
	}
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	h.logger.Log(Event{
		Method:  r.Method,
		Path:    path,
		Outcome: outcome,
		Status:  status,
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func supportedMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete
}

func (h *Handler) allowed(method, path string, header http.Header) bool {
	switch h.mode {
	case ExposureModePrePair:
		return prePairAllowed(method, path)
	case ExposureModeFunnelBootstrap:
		return funnelBootstrapAllowed(method, path)
	case ExposureModePairlingConnect:
		if path == "/pair/start" {
			return false
		}
		if prePairAllowed(method, path) {
			return true
		}
		return hasBearer(header) && Allowed(method, path)
	default:
		return Allowed(method, path)
	}
}

func (h *Handler) allowedForAnyMethod(path string, header http.Header) bool {
	switch h.mode {
	case ExposureModePrePair:
		return prePairAllowed(http.MethodGet, path) || prePairAllowed(http.MethodPost, path)
	case ExposureModeFunnelBootstrap:
		return funnelBootstrapAllowed(http.MethodGet, path) || funnelBootstrapAllowed(http.MethodPost, path)
	case ExposureModePairlingConnect:
		if path == "/pair/start" {
			return true
		}
		if prePairAllowed(http.MethodGet, path) || prePairAllowed(http.MethodPost, path) {
			return true
		}
		return hasBearer(header) && allowedForAnyMethod(path)
	default:
		return allowedForAnyMethod(path)
	}
}

func (h *Handler) requestBodyLimit(method, path string) int64 {
	if method == http.MethodPost && isPrePairClaimPath(path) && (h.mode == ExposureModePrePair || h.mode == ExposureModePairlingConnect || h.mode == ExposureModeFunnelBootstrap) {
		if h.maxBodyBytes <= 0 || prePairMaxBodyBytes < h.maxBodyBytes {
			return prePairMaxBodyBytes
		}
	}
	if method == http.MethodPost && path == "/pairdrop/files" {
		if h.maxBodyBytes <= 0 || pairDropSmallFileMaxBodyBytes < h.maxBodyBytes {
			return pairDropSmallFileMaxBodyBytes
		}
	}
	if method == http.MethodPost && path == "/upload" {
		if h.maxBodyBytes <= 0 || h.maxBodyBytes < chatUploadMaxBodyBytes {
			return chatUploadMaxBodyBytes
		}
	}
	if method == http.MethodPut && pairDropUploadBytesPath(path) {
		if h.maxBodyBytes <= 0 || pairDropUploadChunkMaxBodyBytes < h.maxBodyBytes {
			return pairDropUploadChunkMaxBodyBytes
		}
	}
	return h.maxBodyBytes
}

func (h *Handler) rateLimitPath(method, path string) bool {
	return method == http.MethodPost && isPrePairClaimPath(path) && (h.mode == ExposureModePrePair || h.mode == ExposureModePairlingConnect || h.mode == ExposureModeFunnelBootstrap)
}

func prePairAllowed(method, path string) bool {
	switch method {
	case http.MethodGet:
		return prePairGetPaths[path]
	case http.MethodPost:
		return prePairPostPaths[path]
	default:
		return false
	}
}

// funnelBootstrapAllowed is the public Funnel surface: the most restrictive mode.
// It is a strict subset of the pre-pair set, declared explicitly so it can never
// inherit a widening of prePairGetPaths/prePairPostPaths. It excludes /routez
// (route-topology leak), /pair/claim (legacy plaintext), /pair/start, and the
// reauth paths. There is no bearer post-pair fallthrough.
func funnelBootstrapAllowed(method, path string) bool {
	switch method {
	case http.MethodGet:
		return funnelBootstrapGetPaths[path]
	case http.MethodPost:
		return funnelBootstrapPostPaths[path]
	default:
		return false
	}
}

var funnelBootstrapGetPaths = map[string]bool{
	"/health":   true,
	"/healthz":  true,
	"/readyz":   true,
	"/manifest": true,
}

var funnelBootstrapPostPaths = map[string]bool{
	"/pair/psk-claim": true,
}

func isPrePairClaimPath(path string) bool {
	return path == "/pair/claim" || path == "/pair/psk-claim"
}

func hasBearer(header http.Header) bool {
	return strings.HasPrefix(header.Get("Authorization"), "Bearer ")
}

func Allowed(method, path string) bool {
	if !supportedMethod(method) {
		return false
	}
	switch method {
	case http.MethodGet:
		return getPaths[path] || dynamicGETPath(path)
	case http.MethodPost:
		return postPaths[path] || dynamicPOSTPath(path)
	case http.MethodPut:
		return dynamicPUTPath(path)
	case http.MethodDelete:
		return dynamicDELETEPath(path)
	default:
		return false
	}
}

func allowedForAnyMethod(path string) bool {
	return getPaths[path] || postPaths[path] || dynamicGETPath(path) || dynamicPOSTPath(path) || dynamicPUTPath(path) || dynamicDELETEPath(path)
}

func localUpstream(upstream *url.URL) bool {
	host := upstream.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func dynamicGETPath(path string) bool {
	return sessionExportPath(path) || orchestrationItemPath(path) || orchestrationStreamPath(path) || pairDropFileContentPath(path) || pairDropFileItemPath(path) || pairDropUploadItemPath(path)
}

func dynamicPOSTPath(path string) bool {
	return pickerMCPRestartPath(path) || orchestrationStopPath(path) || pairDropAttachPath(path) || pairDropUploadCompletePath(path)
}

func dynamicPUTPath(path string) bool {
	return pairDropUploadBytesPath(path)
}

func dynamicDELETEPath(path string) bool {
	return pairDropFileItemPath(path) || pairDropUploadItemPath(path)
}

func sessionExportPath(path string) bool {
	return strings.HasPrefix(path, "/sessions/") && strings.HasSuffix(path, "/export")
}

func pickerMCPRestartPath(path string) bool {
	return strings.HasPrefix(path, "/pickers/mcp/") && strings.HasSuffix(path, "/restart")
}

func pairDropFileItemPath(path string) bool {
	if !strings.HasPrefix(path, "/pairdrop/files/") {
		return false
	}
	suffix := strings.TrimPrefix(path, "/pairdrop/files/")
	return suffix != "" && !strings.Contains(suffix, "/")
}

func pairDropFileContentPath(path string) bool {
	if !strings.HasPrefix(path, "/pairdrop/files/") || !strings.HasSuffix(path, "/content") {
		return false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(path, "/pairdrop/files/"), "/content")
	inner = strings.Trim(inner, "/")
	return inner != "" && !strings.Contains(inner, "/")
}

func pairDropAttachPath(path string) bool {
	if !strings.HasPrefix(path, "/pairdrop/files/") || !strings.HasSuffix(path, "/attach") {
		return false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(path, "/pairdrop/files/"), "/attach")
	inner = strings.Trim(inner, "/")
	return inner != "" && !strings.Contains(inner, "/")
}

func pairDropUploadItemPath(path string) bool {
	if !strings.HasPrefix(path, "/pairdrop/uploads/") {
		return false
	}
	suffix := strings.TrimPrefix(path, "/pairdrop/uploads/")
	return suffix != "" && !strings.Contains(suffix, "/")
}

func pairDropUploadBytesPath(path string) bool {
	if !strings.HasPrefix(path, "/pairdrop/uploads/") || !strings.HasSuffix(path, "/bytes") {
		return false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(path, "/pairdrop/uploads/"), "/bytes")
	inner = strings.Trim(inner, "/")
	return inner != "" && !strings.Contains(inner, "/")
}

func pairDropUploadCompletePath(path string) bool {
	if !strings.HasPrefix(path, "/pairdrop/uploads/") || !strings.HasSuffix(path, "/complete") {
		return false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(path, "/pairdrop/uploads/"), "/complete")
	inner = strings.Trim(inner, "/")
	return inner != "" && !strings.Contains(inner, "/")
}

func orchestrationItemPath(path string) bool {
	if !strings.HasPrefix(path, "/orchestrations/") {
		return false
	}
	suffix := strings.TrimPrefix(path, "/orchestrations/")
	return suffix != "" && !strings.Contains(suffix, "/")
}

func orchestrationStopPath(path string) bool {
	if !strings.HasPrefix(path, "/orchestrations/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/orchestrations/"), "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] == "stop"
}

func orchestrationStreamPath(path string) bool {
	if !strings.HasPrefix(path, "/orchestrations/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/orchestrations/"), "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] == "stream"
}

var getPaths = map[string]bool{
	"/activity":                     true,
	"/activity-stream":              true,
	"/aperture-cli/launch-contexts": true,
	"/aperture-cli/providers":       true,
	"/aperture-cli/status":          true,
	"/commands":                     true,
	"/commands-stream":              true,
	"/corpus":                       true,
	"/filesystem/directories":       true,
	"/health":                       true,
	"/health-stream":                true,
	"/healthz":                      true,
	"/readyz":                       true,
	"/routez":                       true,
	"/invocations":                  true,
	"/invocations-stream":           true,
	"/manifest":                     true,
	"/mirror/conflicts":             true,
	"/mirror/projects":              true,
	"/mirror/status":                true,
	"/model-status":                 true,
	"/orchestrations":               true,
	"/personal-context":             true,
	"/pairdrop/events":              true,
	"/pairdrop/files":               true,
	"/pickers/hooks":                true,
	"/pickers/mcp":                  true,
	"/pickers/memory":               true,
	"/pickers/permissions":          true,
	"/pickers/resume":               true,
	"/pickers/resume/preview":       true,
	"/power-state":                  true,
	"/provider-status":              true,
	"/push/status":                  true,
	"/recent-projects":              true,
	"/safety/events":                true,
	"/safety/status":                true,
	"/search":                       true,
	"/sentinel/events":              true,
	"/sentinel/preferences":         true,
	"/sentinel/status":              true,
	"/session-meta":                 true,
	"/session-live-events":          true,
	"/session-source-diagnostics":   true,
	"/sessions":                     true,
	"/sessions-stream":              true,
	"/sessions-visible":             true,
	"/session-runtime-truth":        true,
	"/session-runtime-truth-stream": true,
	"/status":                       true,
	"/substrate-feed":               true,
	"/substrate-status":             true,
	"/terminal-stream":              true,
	"/terminal-stream-diagnostics":  true,
	"/terminal-surface":             true,
	"/terminal-surface-stream":      true,
	"/terminal-surface-v2":          true,
	"/terminal-surface-stream-v2":   true,
	"/terminal-workspace":           true,
	"/terminal-workspace-stream":    true,
	"/tokens":                       true,
	"/transcript":                   true,
	"/transcript-stream":            true,
	"/turn-state-stream":            true,
	"/worker-stats":                 true,
	"/workers":                      true,
	"/workstate-feed":               true,
}

var postPaths = map[string]bool{
	"/aperture-cli/open":                     true,
	"/cross-provider-action":                 true,
	"/inject":                                true,
	"/inject-now":                            true,
	"/interrupt":                             true,
	"/llm-route":                             true,
	"/llm-route-stream":                      true,
	"/mirror/flush":                          true,
	"/mirror/resume":                         true,
	"/open":                                  true,
	"/orchestrations":                        true,
	"/pair/claim":                            true,
	"/pair/psk-claim":                        true,
	"/pair/revoke":                           true,
	"/pair/rotate-token":                     true,
	"/pair/start":                            true,
	"/pairling-tools/run":                    true,
	"/pairdrop/files":                        true,
	"/pairdrop/maintenance/cleanup-partials": true,
	"/pairdrop/uploads":                      true,
	"/phone-tools/availability":              true,
	"/phone-tools/next":                      true,
	"/phone-tools/result":                    true,
	"/push/live-activity-test":               true,
	"/push/live-activity-token":              true,
	"/push/permission/allow":                 true,
	"/push/preferences":                      true,
	"/push/test":                             true,
	"/resume-session":                        true,
	"/safety/ack":                            true,
	"/send-text":                             true,
	"/sentinel/evaluate-now":                 true,
	"/sentinel/preferences":                  true,
	"/sentinel/snooze":                       true,
	"/sigint":                                true,
	"/sigterm":                               true,
	"/spawn-session":                         true,
	"/terminal-control":                      true,
	"/upload":                                true,
	"/worker-kill":                           true,
}

var prePairGetPaths = map[string]bool{
	"/health":   true,
	"/healthz":  true,
	"/readyz":   true,
	"/routez":   true,
	"/manifest": true,
}

var prePairPostPaths = map[string]bool{
	"/pair/claim":     true,
	"/pair/psk-claim": true,
}

type MemoryRateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
	now    func() time.Time
}

func NewMemoryRateLimiter(limit int, window time.Duration) *MemoryRateLimiter {
	if limit <= 0 {
		limit = 20
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &MemoryRateLimiter{
		limit:  limit,
		window: window,
		hits:   map[string][]time.Time{},
		now:    time.Now,
	}
}

func (l *MemoryRateLimiter) Allow(remoteAddr, method, path string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cutoff := now.Add(-l.window)
	key := rateLimitKey(remoteAddr, method, path)
	existing := l.hits[key]
	kept := existing[:0]
	for _, ts := range existing {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= l.limit {
		l.hits[key] = kept
		return false
	}
	kept = append(kept, now)
	l.hits[key] = kept
	return true
}

func rateLimitKey(remoteAddr, method, path string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil || host == "" {
		host = remoteAddr
	}
	return host + "|" + method + "|" + path
}

func joinPath(base, path string) string {
	if base == "" || base == "/" {
		if path == "" {
			return "/"
		}
		return path
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}
