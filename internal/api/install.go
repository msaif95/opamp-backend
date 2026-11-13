package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/msaif95/opamp-backend/internal/auth"
)

// DefaultCollectorVersion is offered when the caller does not pick one.
const DefaultCollectorVersion = "0.164.0"

var (
	installPlatforms = map[string]bool{"linux_amd64": true, "linux_arm64": true, "darwin_amd64": true, "darwin_arm64": true}
	versionRE        = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	labelKeyRE       = regexp.MustCompile(`^[A-Za-z0-9._-]{1,63}$`)
	labelValueRE     = regexp.MustCompile(`^[A-Za-z0-9._:/@-]{1,128}$`)
)

// InstallConfig is what the install command needs to know about how
// collectors reach this deployment.
type InstallConfig struct {
	// EndpointURL is the OpAMP URL collectors connect to, e.g. wss://opamp-agents.example.com/v1/opamp.
	EndpointURL string
	// CAFile, if set, is the CA collectors must trust to verify the endpoint.
	CAFile string
}

// installCommand issues an agent API key and returns a script that installs
// the stock OpenTelemetry Collector and OpAMP Supervisor, already pointed
// at this deployment with that key and the given labels.
func (s *Server) installCommand(w http.ResponseWriter, r *http.Request) {
	req := struct {
		Platform    string            `json:"platform"`
		Version     string            `json:"version"`
		Labels      map[string]string `json:"labels"`
		KeyName     string            `json:"key_name"`
		ExpiresDays int               `json:"expires_days"`
	}{Version: DefaultCollectorVersion}
	if !decode(w, r, &req) {
		return
	}
	if s.Install.EndpointURL == "" {
		writeError(w, http.StatusConflict, "the agent endpoint is not configured (AGENT_ENDPOINT_URL)")
		return
	}
	switch {
	case !installPlatforms[req.Platform]:
		writeError(w, http.StatusBadRequest, "platform must be linux_amd64, linux_arm64, darwin_amd64 or darwin_arm64")
		return
	case !versionRE.MatchString(req.Version):
		writeError(w, http.StatusBadRequest, "version must look like 0.164.0")
		return
	case strings.TrimSpace(req.KeyName) == "":
		writeError(w, http.StatusBadRequest, "key_name is required")
		return
	case req.ExpiresDays < 0:
		writeError(w, http.StatusBadRequest, "expires_days must be 0 or more")
		return
	}
	// Labels end up in a shell script and a YAML file; keep them to a safe alphabet.
	for k, v := range req.Labels {
		if !labelKeyRE.MatchString(k) || !labelValueRE.MatchString(v) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("label %q: keys and values may only use letters, digits and . _ - (values also : / @)", k))
			return
		}
	}
	var ca []byte
	if s.Install.CAFile != "" {
		var err error
		if ca, err = os.ReadFile(s.Install.CAFile); err != nil {
			s.internal(w, r, err)
			return
		}
	}

	u, _ := auth.UserFrom(r.Context())
	var expires *time.Time
	if req.ExpiresDays > 0 {
		t := time.Now().AddDate(0, 0, req.ExpiresDays)
		expires = &t
	}
	key, err := s.Agents.IssueAPIKey(r.Context(), strings.TrimSpace(req.KeyName), u.Subject, expires)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r.Context(), u.Subject, u.Provider, "agent.install_command", "credential", key.ID.String(),
		map[string]any{"platform": req.Platform, "version": req.Version, "labels": req.Labels, "key_name": key.Name})
	writeJSON(w, http.StatusCreated, map[string]any{
		"script":     installScript(s.Install.EndpointURL, string(ca), key.Secret, req.Platform, req.Version, req.Labels),
		"api_key_id": key.ID,
	})
}

func installScript(endpoint, caPEM, apiKey, platform, version string, labels map[string]string) string {
	osName, arch, _ := strings.Cut(platform, "_")
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var attrs strings.Builder
	for _, k := range keys {
		v, _ := json.Marshal(labels[k]) // a JSON string is a valid YAML scalar
		fmt.Fprintf(&attrs, "      %s: %s\n", k, v)
	}
	description := ""
	if attrs.Len() > 0 {
		description = "  description:\n    non_identifying_attributes:\n" + attrs.String()
	}
	tls, writeCA := "", ""
	switch {
	case strings.HasPrefix(endpoint, "ws://"):
		tls = "  tls:\n    insecure: true\n"
	case caPEM != "":
		tls = "  tls:\n    ca_file: __DIR__/ca.crt\n"
		writeCA = "cat > \"$INSTALL_DIR/ca.crt\" <<'OPAMP_CA'\n" + strings.TrimRight(caPEM, "\n") + "\nOPAMP_CA\n"
	}
	return strings.NewReplacer(
		"__VERSION__", version, "__OS__", osName, "__ARCH__", arch, "__ENDPOINT__", endpoint,
		"__KEY__", apiKey, "__TLS__", tls, "__DESCRIPTION__", description, "__WRITE_CA__", writeCA,
		"__HOST_CHECK__", hostCheck(osName, arch), "__SERVICE__", serviceSection[osName], "__PLATFORM_NAME__", platformName(osName, arch),
	).Replace(installTemplate)
}

const installTemplate = `#!/bin/sh
# Installs the OpenTelemetry Collector (contrib) and the OpAMP Supervisor on __PLATFORM_NAME__, connected to OpAMP Fleet.
# This script contains an agent API key: treat it as a secret.
set -eu

VERSION="__VERSION__"
OS="__OS__"
ARCH="__ARCH__"
INSTALL_DIR="${INSTALL_DIR:-/opt/opamp-supervisor}"
BASE="https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download"

__HOST_CHECK__

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -c1-64; else shasum -a 256 "$1" | cut -c1-64; fi; }
fetch() {
  curl -fsSL -o "$2" "$1"
  curl -fsSL -o "$2.sha256" "$1.sha256"
  if [ "$(sha256 "$2")" != "$(cut -c1-64 "$2.sha256")" ]; then
    echo "Checksum mismatch for $2; refusing to install." >&2
    exit 1
  fi
  rm -f "$2.sha256"
}

umask 077
mkdir -p "$INSTALL_DIR/storage"
cd "$INSTALL_DIR"

echo "Downloading OpAMP Supervisor and Collector $VERSION for ${OS}_${ARCH}..."
fetch "$BASE/cmd%2Fopampsupervisor%2Fv$VERSION/opampsupervisor_${VERSION}_${OS}_${ARCH}" opampsupervisor
fetch "$BASE/v$VERSION/otelcol-contrib_${VERSION}_${OS}_${ARCH}.tar.gz" otelcol-contrib.tar.gz
tar xzf otelcol-contrib.tar.gz otelcol-contrib
rm -f otelcol-contrib.tar.gz
chmod 755 opampsupervisor otelcol-contrib

__WRITE_CA__
sed "s|__DIR__|$INSTALL_DIR|g" > supervisor.yaml <<'OPAMP_CONFIG'
server:
  endpoint: __ENDPOINT__
  headers:
    Authorization: "Bearer __KEY__"
__TLS__capabilities:
  accepts_remote_config: true
  reports_effective_config: true
  reports_health: true
  reports_heartbeat: true
agent:
  executable: __DIR__/otelcol-contrib
__DESCRIPTION__storage:
  directory: __DIR__/storage
OPAMP_CONFIG
chmod 600 supervisor.yaml

__SERVICE__`

// The script is specific to one platform: it contains only that platform's
// host check and service set-up, so a macOS script has no Linux steps in it.

func platformName(osName, arch string) string {
	name := map[string]string{"linux": "Linux", "darwin": "macOS"}[osName]
	return name + " (" + map[string]string{"amd64": "x86-64", "arm64": "ARM64"}[arch] + ")"
}

func hostCheck(osName, arch string) string {
	kernel := map[string]string{"linux": "Linux", "darwin": "Darwin"}[osName]
	// uname -m names: Linux says aarch64 where macOS says arm64.
	machines := map[string]string{"amd64": "x86_64", "arm64": "arm64 | aarch64"}[arch]
	return `if [ "$(uname -s)" != "` + kernel + `" ]; then
  echo "This script is for ` + platformName(osName, arch) + ` but this machine runs $(uname -s)." >&2
  exit 1
fi
case "$(uname -m)" in
  ` + machines + `) ;;
  *)
    echo "This script is for ` + platformName(osName, arch) + ` but this machine is $(uname -m)." >&2
    exit 1
    ;;
esac`
}

var serviceSection = map[string]string{
	"linux": `if command -v systemctl >/dev/null 2>&1 && [ "$(id -u)" = 0 ]; then
  cat > /etc/systemd/system/opamp-supervisor.service <<UNIT
[Unit]
Description=OpAMP Supervisor (OpenTelemetry Collector)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$INSTALL_DIR/opampsupervisor --config $INSTALL_DIR/supervisor.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now opamp-supervisor
  echo "Installed and started as the systemd service opamp-supervisor."
else
  echo "Installed in $INSTALL_DIR. Start it with:"
  echo "  $INSTALL_DIR/opampsupervisor --config $INSTALL_DIR/supervisor.yaml"
fi
`,
	"darwin": `# Downloaded binaries may carry the quarantine flag, which stops them starting unattended.
xattr -d com.apple.quarantine opampsupervisor otelcol-contrib 2>/dev/null || true

if [ "$(id -u)" = 0 ]; then
  PLIST=/Library/LaunchDaemons/io.opentelemetry.opamp-supervisor.plist
  cat > "$PLIST" <<PLIST_BODY
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.opentelemetry.opamp-supervisor</string>
  <key>ProgramArguments</key>
  <array>
    <string>$INSTALL_DIR/opampsupervisor</string>
    <string>--config</string>
    <string>$INSTALL_DIR/supervisor.yaml</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$INSTALL_DIR/supervisor.log</string>
  <key>StandardErrorPath</key><string>$INSTALL_DIR/supervisor.log</string>
</dict>
</plist>
PLIST_BODY
  chmod 644 "$PLIST"
  launchctl bootout system "$PLIST" 2>/dev/null || true
  launchctl bootstrap system "$PLIST"
  echo "Installed and started as the launchd service io.opentelemetry.opamp-supervisor."
else
  echo "Installed in $INSTALL_DIR. Start it with:"
  echo "  $INSTALL_DIR/opampsupervisor --config $INSTALL_DIR/supervisor.yaml"
  echo "Run this script with sudo instead to install it as a launchd service that starts at boot."
fi
`,
}
