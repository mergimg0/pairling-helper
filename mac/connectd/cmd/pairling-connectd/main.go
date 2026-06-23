package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dev.pairling/connectd/internal/gateway"
	runtimecfg "dev.pairling/connectd/internal/runtime"
	"dev.pairling/connectd/internal/status"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("pairling-connectd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	home, _ := os.UserHomeDir()
	appSupport := runtimecfg.DefaultAppSupportRoot(home)
	defaultStateDir := runtimecfg.DefaultStateDir(home)
	defaultHostname := runtimecfg.StableHostname(appSupport, defaultStateDir)

	upstreamRaw := fs.String("upstream", "http://127.0.0.1:7773", "Pairling daemon upstream URL")
	listenAddr := fs.String("listen", ":7773", "tailnet-only service listen address")
	statusAddr := fs.String("status-addr", "127.0.0.1:7774", "loopback status server address")
	stateDir := fs.String("state-dir", defaultStateDir, "tsnet state directory")
	hostname := fs.String("hostname", defaultHostname, "tailnet hostname for this Pairling Connect node")
	controlURL := fs.String("control-url", "", "advanced: custom Tailscale-compatible control server URL")
	maxBodyBytes := fs.Int64("max-body-bytes", 1_000_000, "maximum proxied request body size")
	verbose := fs.Bool("verbose", false, "enable verbose tsnet backend logs")
	// WS1: a tagged auth key (minted from an OAuth client scoped to
	// tag:pairling-connect) registers this node pre-authorized AND with key
	// expiry disabled — no 180-day re-auth cliff, no per-node REST call.
	// Empty keeps the legacy interactive browser-auth path (back-compat).
	authKeyTag := fs.String("auth-key-tag", defaultAuthKeyTag(), "tag applied to this node when registering with an auth key")
	funnelDefault := false
	switch strings.ToLower(strings.TrimSpace(os.Getenv("PAIRLING_CONNECT_FUNNEL"))) {
	case "1", "true", "on", "yes":
		funnelDefault = true
	}
	funnelEnabled := fs.Bool("funnel", funnelDefault, "expose a public Tailscale Funnel listener for the pre-pair bootstrap claim (off by default)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if strings.TrimSpace(*hostname) == "" {
		*hostname = runtimecfg.HostnameFromInstallID("")
	}

	upstream, err := url.Parse(*upstreamRaw)
	if err != nil {
		log.Printf("invalid upstream: %v", err)
		return 2
	}
	if err := ensurePrivateDir(*stateDir); err != nil {
		log.Printf("cannot prepare state dir: %v", err)
		return 1
	}

	statusStore := status.NewStore(*hostname)
	statusStore.SetControlURLMode(controlURLMode(*controlURL))
	statusStore.SetListenPort(listenPort(*listenAddr))
	statusStore.SetConnectdVersion(status.DefaultConnectdVersion)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	statusServer := startStatusServer(*statusAddr, statusStore)
	defer shutdownHTTPServer(statusServer)

	go monitorUpstream(ctx, upstream, statusStore)

	srv := &tsnet.Server{
		Dir:        *stateDir,
		Hostname:   *hostname,
		ControlURL: strings.TrimSpace(*controlURL),
		UserLogf:   userLogf(statusStore),
	}
	// WS1: tagged auth-key registration. A tagged node never expires its key,
	// eliminating the 180-day re-auth cliff without any Tailscale REST call.
	if authKey := loadTailscaleAuthKey(appSupport); authKey != "" {
		srv.AuthKey = authKey
		if tag := strings.TrimSpace(*authKeyTag); tag != "" {
			srv.AdvertiseTags = []string{tag}
		}
		statusStore.SetAuthKeyMode("tagged")
		log.Printf("pairling-connectd registering with tagged auth key (tag=%s)", strings.TrimSpace(*authKeyTag))
	} else {
		statusStore.SetAuthKeyMode("interactive")
	}
	if *verbose {
		srv.Logf = func(format string, args ...any) {
			log.Printf("tsnet: "+format, args...)
		}
	}

	handler, err := gateway.NewHandler(gateway.Options{
		Upstream:     upstream,
		MaxBodyBytes: *maxBodyBytes,
		Mode:         gateway.ExposureModePairlingConnect,
		Logger:       gatewayLogger{store: statusStore},
		RateLimiter:  gateway.NewMemoryRateLimiter(20, 5*time.Minute),
		PeerNodeResolver: tailscalePeerNodeResolver{localClient: func() (whoIsClient, error) {
			return srv.LocalClient()
		}},
	})
	if err != nil {
		log.Printf("cannot create gateway: %v", err)
		return 1
	}

	ln, err := srv.Listen("tcp", *listenAddr)
	if err != nil {
		statusStore.SetLastError(err.Error())
		log.Printf("cannot start tailnet listener: %v", err)
		return 1
	}
	defer srv.Close()
	statusStore.SetListenerRunning(true)
	go monitorTailnetIPs(ctx, srv, statusStore)

	// Increment 1: optional public Funnel listener for the pre-pair bootstrap
	// claim, off by default. A SEPARATE handler in ExposureModeFunnelBootstrap,
	// never the tailnet pairling_connect handler, so the bearer post-pair surface
	// is structurally unreachable over Funnel. A failure to open is logged and
	// recorded but does not bring down the tailnet listener.
	// Increment 8: PSK-required boot precondition. On a funnel-enabled install the
	// legacy plaintext /pair/claim must be impossible, so refuse to open the
	// public listener unless PSK is required (the daemon default). A PSK-off
	// misconfiguration would otherwise risk a secret-on-the-wire claim path.
	pskRequired := true
	switch strings.ToLower(strings.TrimSpace(os.Getenv("PAIRLING_PSK_REQUIRED"))) {
	case "0", "false", "no", "off":
		pskRequired = false
	}
	if *funnelEnabled && !pskRequired {
		log.Printf("refusing to open funnel listener: PAIRLING_PSK_REQUIRED must be on for a funnel-enabled install")
	}
	var funnelServer *http.Server
	if *funnelEnabled && pskRequired {
		funnelMacIDHash := ""
		if id := strings.TrimSpace(runtimecfg.LoadInstallID(appSupport)); id != "" {
			sum := sha256.Sum256([]byte(id))
			funnelMacIDHash = hex.EncodeToString(sum[:])
		}
		funnelHandler, ferr := gateway.NewHandler(gateway.Options{
			Upstream:        upstream,
			MaxBodyBytes:    *maxBodyBytes,
			Mode:            gateway.ExposureModeFunnelBootstrap,
			Logger:          gatewayLogger{store: statusStore},
			FunnelLimiter:   gateway.NewFunnelLimiter(120, 5, 6),
			FunnelMacIDHash: funnelMacIDHash,
		})
		if ferr != nil {
			log.Printf("cannot create funnel gateway: %v", ferr)
			return 1
		}
		funnelLn, ferr := srv.ListenFunnel("tcp", ":443", tsnet.FunnelOnly())
		if ferr != nil {
			statusStore.SetLastError(ferr.Error())
			log.Printf("cannot start funnel listener: %v", ferr)
		} else {
			funnelServer = &http.Server{Handler: funnelHandler, ReadHeaderTimeout: 10 * time.Second}
			if domains := srv.CertDomains(); len(domains) > 0 {
				statusStore.SetFunnelHostname(domains[0])
				log.Printf("pairling-connectd funnel listener open host=%s", domains[0])
			}
			go func() {
				if serr := funnelServer.Serve(funnelLn); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
					statusStore.SetLastError(serr.Error())
					log.Printf("funnel server stopped: %v", serr)
				}
			}()
		}
	}

	log.Printf("pairling-connectd hostname=%s state_dir=%s listen=%s upstream=%s status=%s", *hostname, *stateDir, *listenAddr, upstream.String(), *statusAddr)
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		shutdownHTTPServer(server)
		shutdownHTTPServer(funnelServer)
		return 0
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			statusStore.SetLastError(err.Error())
			log.Printf("tailnet server stopped: %v", err)
			return 1
		}
		return 0
	}
}

func controlURLMode(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return status.DefaultControlURLMode
	}
	return status.CustomControlURLMode
}

// defaultAuthKeyTag is the ACL tag applied to Pairling Connect nodes that
// register with a tagged auth key. Tagged nodes do not expire their keys.
func defaultAuthKeyTag() string {
	if tag := strings.TrimSpace(os.Getenv("PAIRLING_TS_AUTHKEY_TAG")); tag != "" {
		return tag
	}
	return "tag:pairling-connect"
}

// loadTailscaleAuthKey resolves a tagged auth key, preferring the environment
// (PAIRLING_TS_AUTHKEY) over a mode-600 credential file under Application
// Support. Returns "" when neither is present (legacy interactive auth).
func loadTailscaleAuthKey(appSupport string) string {
	if key := strings.TrimSpace(os.Getenv("PAIRLING_TS_AUTHKEY")); key != "" {
		return key
	}
	path := filepath.Join(appSupport, "connectd", "connectd-ts-authkey")
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func listenPort(addr string) int {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return status.DefaultListenPort
	}
	_, portString, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.HasPrefix(addr, ":") {
			portString = strings.TrimPrefix(addr, ":")
		} else {
			idx := strings.LastIndex(addr, ":")
			if idx >= 0 && idx < len(addr)-1 {
				portString = addr[idx+1:]
			}
		}
	}
	port, err := strconv.Atoi(portString)
	if err != nil || port <= 0 {
		return status.DefaultListenPort
	}
	return port
}

type gatewayLogger struct {
	store *status.Store
}

func (l gatewayLogger) Log(event gateway.Event) {
	log.Printf("gateway method=%s path=%s status=%d outcome=%s", event.Method, event.Path, event.Status, event.Outcome)
	if l.store != nil {
		l.store.RecordGatewayEvent(event.Method, event.Path, event.Status, event.Outcome)
	}
}

func userLogf(store *status.Store) func(string, ...any) {
	return func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		redacted := status.Redact(msg)
		log.Printf("tailscale: %s", redacted)
		if strings.Contains(msg, "login.tailscale.com") || strings.Contains(strings.ToLower(msg), "auth") {
			store.SetAuthPending(msg)
		}
	}
}

func ensurePrivateDir(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("state dir is required")
	}
	cleaned := filepath.Clean(path)
	if err := os.MkdirAll(cleaned, 0o700); err != nil {
		return err
	}
	return os.Chmod(cleaned, 0o700)
}

func startStatusServer(addr string, store *status.Store) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/status", store.Handler())
	mux.HandleFunc("/auth/open", func(w http.ResponseWriter, r *http.Request) {
		handleAuthOpen(w, r, store)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}` + "\n"))
	})
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("status server stopped: %v", err)
			store.SetLastError(err.Error())
		}
	}()
	return server
}

var openAuthURL = func(rawURL string) error {
	return exec.Command("/usr/bin/open", rawURL).Start()
}

func handleAuthOpen(w http.ResponseWriter, r *http.Request, store *status.Store) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !isLoopbackRemote(r.RemoteAddr) {
		http.Error(w, "loopback required", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	rawURL, ok := store.AuthURLForOpen()
	if !ok {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":               false,
			"opened":           false,
			"auth_url_present": store.Snapshot().AuthURLPresent,
			"error":            "Pairling Connect auth URL is not available yet.",
		})
		return
	}
	if err := openAuthURL(rawURL); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":               false,
			"opened":           false,
			"auth_url_present": true,
			"error":            "Pairling Connect could not open browser approval.",
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":               true,
		"opened":           true,
		"auth_url_present": true,
	})
}

func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

func shutdownHTTPServer(server *http.Server) {
	if server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func monitorUpstream(ctx context.Context, upstream *url.URL, store *status.Store) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	check := func() {
		store.SetUpstreamReachable(checkUpstream(upstream))
	}
	check()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

func checkUpstream(upstream *url.URL) bool {
	if upstream == nil {
		return false
	}
	healthURL := *upstream
	healthURL.Path = strings.TrimRight(healthURL.Path, "/") + "/readyz"
	healthURL.RawQuery = ""
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(healthURL.String())
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode < 500
}

func monitorTailnetIPs(ctx context.Context, srv *tsnet.Server, store *status.Store) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	update := func() {
		identity := NodeIdentity{}
		if lc, err := srv.LocalClient(); err == nil {
			if lock, err := lc.NetworkLockStatus(ctx); err == nil {
				store.SetTailnetLockEnabled(lock.Enabled)
			}
			if st, err := lc.StatusWithoutPeers(ctx); err == nil {
				identity = nodeIdentityFromStatus(st)
				store.SetTailnetIdentity(identity.NodeID, identity.Tags, identity.TailnetIPs)
			}
		}
		if len(identity.TailnetIPs) > 0 {
			store.SetTailnetIP(identity.TailnetIPs[0])
			store.SetAuthenticated()
			return
		}
		ip4, _ := srv.TailscaleIPs()
		if ip4.IsValid() {
			store.SetTailnetIP(ip4.String())
			store.SetAuthenticated()
			return
		}
		store.SetTailnetIdentity("", nil, nil)
		store.SetAuthPending("")
	}
	update()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			update()
		}
	}
}

type NodeIdentity struct {
	NodeID     string
	Tags       []string
	TailnetIPs []string
}

type whoIsClient interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

type tailscalePeerNodeResolver struct {
	localClient func() (whoIsClient, error)
}

func (r tailscalePeerNodeResolver) PeerNodeID(ctx context.Context, remoteAddr string) (string, bool) {
	if r.localClient == nil {
		return "", false
	}
	lc, err := r.localClient()
	if err != nil || lc == nil {
		return "", false
	}
	who, err := lc.WhoIs(ctx, remoteAddr)
	if err != nil {
		return "", false
	}
	return peerNodeIDFromWhoIs(who)
}

func peerNodeIDFromWhoIs(who *apitype.WhoIsResponse) (string, bool) {
	if who == nil || who.Node == nil {
		return "", false
	}
	nodeID := strings.TrimSpace(string(who.Node.StableID))
	if nodeID == "" {
		return "", false
	}
	for _, tag := range who.Node.Tags {
		if tag == "tag:pairling-phone" {
			return nodeID, true
		}
	}
	return "", false
}

func nodeIdentityFromStatus(st *ipnstate.Status) NodeIdentity {
	if st == nil || st.Self == nil {
		return NodeIdentity{}
	}
	self := st.Self
	identity := NodeIdentity{NodeID: string(self.ID)}
	if self.Tags != nil {
		for _, tag := range self.Tags.All() {
			identity.Tags = append(identity.Tags, tag)
		}
	}
	for _, ip := range self.TailscaleIPs {
		if ip.IsValid() {
			identity.TailnetIPs = append(identity.TailnetIPs, ip.String())
		}
	}
	return identity
}
