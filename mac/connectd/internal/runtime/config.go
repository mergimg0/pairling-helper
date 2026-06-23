package runtime

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

func DefaultAppSupportRoot(home string) string {
	if v := os.Getenv("PAIRLING_APP_SUPPORT_ROOT"); v != "" {
		return v
	}
	if v := os.Getenv("COMPANION_APP_SUPPORT_ROOT"); v != "" {
		return v
	}
	if home == "" {
		if detected, err := os.UserHomeDir(); err == nil {
			home = detected
		}
	}
	return filepath.Join(home, "Library", "Application Support", "Pairling")
}

func DefaultStateDir(home string) string {
	return filepath.Join(DefaultAppSupportRoot(home), "connectd", "tsnet-state")
}

func LoadInstallID(appSupportRoot string) string {
	for _, candidate := range []string{
		filepath.Join(appSupportRoot, "config.json"),
		filepath.Join(appSupportRoot, "state", "install-id"),
	} {
		value := loadInstallIDCandidate(candidate)
		if value != "" {
			return value
		}
	}
	return ""
}

func HostnameFromInstallID(installID string) string {
	slug := sanitizeHostnamePart(installID)
	if slug == "" {
		slug = randomSlug()
	}
	if len(slug) > 11 {
		slug = strings.Trim(slug[:11], "-")
	}
	if slug == "" {
		slug = "mac"
	}
	return "pairling-" + slug
}

// StableHostname returns a tailnet hostname that survives a regenerated
// install_id. It persists the first computed hostname under the state directory
// and reuses it thereafter, so a reinstall that only changes install_id does not
// change the *.ts.net name, which would otherwise reset the Funnel certificate.
// If the state directory is wiped, a fresh node and name are created regardless.
func StableHostname(appSupportRoot, stateDir string) string {
	path := filepath.Join(stateDir, "hostname")
	if data, err := os.ReadFile(path); err == nil {
		if name := strings.TrimSpace(string(data)); name != "" {
			return name
		}
	}
	name := HostnameFromInstallID(LoadInstallID(appSupportRoot))
	if err := os.MkdirAll(stateDir, 0o700); err == nil {
		_ = os.WriteFile(path, []byte(name+"\n"), 0o600)
	}
	return name
}

func loadInstallIDCandidate(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if strings.HasSuffix(path, ".json") {
		var payload struct {
			InstallID string `json:"install_id"`
		}
		if json.Unmarshal(data, &payload) == nil {
			return strings.TrimSpace(payload.InstallID)
		}
		return ""
	}
	return strings.TrimSpace(string(data))
}

func sanitizeHostnamePart(value string) string {
	var b strings.Builder
	lastHyphen := false
	for _, r := range strings.ToLower(value) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			lastHyphen = false
			continue
		}
		if !lastHyphen {
			b.WriteByte('-')
			lastHyphen = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func randomSlug() string {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "mac"
	}
	return hex.EncodeToString(buf[:])
}
