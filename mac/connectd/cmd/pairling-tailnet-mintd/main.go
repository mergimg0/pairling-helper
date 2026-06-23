package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	var (
		secretPath    = flag.String("secret-path", "/Library/Application Support/Pairling/mint/client_secret.json", "OAuth client credential JSON")
		socketPath    = flag.String("socket-path", "/Library/Application Support/Pairling/run/mintd/mintd.sock", "Unix socket path")
		statePath     = flag.String("state-path", "/Library/Application Support/Pairling/mint/state.json", "persistent rate-limit state JSON")
		auditPath     = flag.String("audit-path", "/Library/Application Support/Pairling/mint/audit.jsonl", "audit JSONL path")
		alertPath     = flag.String("alert-path", "/Library/Application Support/Pairling/run/mintd/alerts.jsonl", "health-readable alert JSONL path")
		apiBaseURL    = flag.String("api-base-url", "https://api.tailscale.com/api/v2", "Tailscale API base URL")
		oauthURL      = flag.String("oauth-url", "https://api.tailscale.com/api/v2/oauth/token", "Tailscale OAuth token URL")
		authorizedUID = flag.Int("authorized-uid", -1, "only this peer uid may request mints")
	)
	flag.Parse()

	b, err := NewBroker(BrokerConfig{
		SecretPath: *secretPath,
		StatePath:  *statePath,
		AuditPath:  *auditPath,
		AlertPath:  *alertPath,
		OAuthURL:   *oauthURL,
		APIBaseURL: *apiBaseURL,
		LockStatus: defaultLockStatus,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := b.ServeUnix(ctx, *socketPath, *authorizedUID); err != nil {
		log.Fatal(err)
	}
}

func defaultLockStatus(ctx context.Context) (bool, error) {
	if locked, err := lockStatusFromConnectdStatus(ctx, "http://127.0.0.1:7774/status"); err == nil {
		return locked, nil
	}
	return lockStatusFromCandidates(ctx, []string{
		"/opt/homebrew/bin/tailscale",
		"/Applications/Tailscale.app/Contents/MacOS/Tailscale",
		"tailscale",
	})
}

func lockStatusFromConnectdStatus(ctx context.Context, statusURL string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
	if err != nil {
		return false, err
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("connectd status returned %s", resp.Status)
	}
	var body struct {
		TailnetLockEnabled *bool `json:"tailnet_lock_enabled"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, err
	}
	if body.TailnetLockEnabled == nil {
		return false, errors.New("connectd status omitted tailnet_lock_enabled")
	}
	return *body.TailnetLockEnabled, nil
}

func lockStatusFromCandidates(ctx context.Context, candidates []string) (bool, error) {
	var errs []error
	for _, bin := range candidates {
		out, err := exec.CommandContext(ctx, bin, "lock", "status").CombinedOutput()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", bin, err))
			continue
		}
		text := strings.ToLower(string(out))
		if strings.Contains(text, "tailscale gui failed to start") {
			errs = append(errs, fmt.Errorf("%s: gui unavailable", bin))
			continue
		}
		if strings.Contains(text, "not enabled") || strings.Contains(text, "disabled") {
			return false, nil
		}
		if strings.Contains(text, "enabled") {
			return true, nil
		}
		return false, fmt.Errorf("unrecognized tailscale lock status: %q", strings.TrimSpace(string(out)))
	}
	return false, errors.New("tailscale lock status unavailable: " + joinErrors(errs))
}

func joinErrors(errs []error) string {
	parts := make([]string, 0, len(errs))
	for _, err := range errs {
		parts = append(parts, err.Error())
	}
	if len(parts) == 0 {
		return "no candidates"
	}
	return strconv.Quote(strings.Join(parts, "; "))
}
