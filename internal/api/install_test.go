package api

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The generated script must be valid shell and write a valid Supervisor config.
func TestInstallScript(t *testing.T) {
	labels := map[string]string{"env": "prod", "team": "sre", "dc": "iad1"}
	for name, tc := range map[string]struct {
		endpoint, ca string
		wantTLS      string
	}{
		"plaintext dev":   {"ws://localhost:4320/v1/opamp", "", "insecure: true"},
		"private CA":      {"wss://opamp.example.com/v1/opamp", "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n", "ca_file: /opt/x/ca.crt"},
		"public CA (wss)": {"wss://opamp.example.com/v1/opamp", "", ""},
	} {
		script := installScript(tc.endpoint, tc.ca, "opamp_secret-KEY_123", "linux_amd64", "0.164.0", labels)
		if strings.Contains(script, "__") && strings.Contains(strings.ReplaceAll(script, "__DIR__", ""), "__") {
			t.Errorf("%s: unreplaced placeholder in script", name)
		}
		path := filepath.Join(t.TempDir(), "install.sh")
		if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
			t.Fatalf("%s: script is not valid shell: %v\n%s", name, err, out)
		}

		// Extract the Supervisor config the script would write and parse it.
		_, rest, _ := strings.Cut(script, "<<'OPAMP_CONFIG'\n")
		body, _, _ := strings.Cut(rest, "\nOPAMP_CONFIG")
		body = strings.ReplaceAll(body, "__DIR__", "/opt/x")
		var cfg struct {
			Server struct {
				Endpoint string
				Headers  map[string]string
			}
			Capabilities map[string]bool
			Agent        struct {
				Executable  string
				Description struct {
					Attrs map[string]string `yaml:"non_identifying_attributes"`
				}
			}
		}
		if err := yaml.Unmarshal([]byte(body), &cfg); err != nil {
			t.Fatalf("%s: supervisor config is not valid YAML: %v\n%s", name, err, body)
		}
		if cfg.Server.Endpoint != tc.endpoint || cfg.Server.Headers["Authorization"] != "Bearer opamp_secret-KEY_123" ||
			!cfg.Capabilities["accepts_remote_config"] || cfg.Agent.Executable != "/opt/x/otelcol-contrib" ||
			cfg.Agent.Description.Attrs["dc"] != "iad1" || len(cfg.Agent.Description.Attrs) != 3 {
			t.Errorf("%s: unexpected supervisor config: %+v", name, cfg)
		}
		if tc.wantTLS != "" && !strings.Contains(body, tc.wantTLS) {
			t.Errorf("%s: config lacks %q", name, tc.wantTLS)
		}
		if tc.wantTLS == "" && strings.Contains(body, "tls:") {
			t.Errorf("%s: unexpected tls block", name)
		}
		if (tc.ca != "") != strings.Contains(script, "OPAMP_CA") {
			t.Errorf("%s: CA file handling wrong", name)
		}
	}
}

func TestInstallLabelAlphabet(t *testing.T) {
	for v, ok := range map[string]bool{"prod": true, "us-east-1": true, "a/b:c@d": true, "": false, "x y": false, `a"b`: false, "$(id)": false, "a\nb": false} {
		if labelValueRE.MatchString(v) != ok {
			t.Errorf("value %q: accepted=%v, want %v", v, !ok, ok)
		}
	}
}

// A script must contain only its own platform's steps: a macOS script that
// carried the Linux service set-up read as if it had been generated for Linux.
func TestInstallScriptIsPlatformSpecific(t *testing.T) {
	for platform, tc := range map[string]struct{ want, forbidden []string }{
		"darwin_arm64": {[]string{`OS="darwin"`, "macOS (ARM64)", "launchctl", `"Darwin"`}, []string{"systemctl", "systemd", "Linux", "linux"}},
		"darwin_amd64": {[]string{"macOS (x86-64)", "x86_64)"}, []string{"systemctl", "linux"}},
		"linux_amd64":  {[]string{`OS="linux"`, "Linux (x86-64)", "systemctl"}, []string{"launchctl", "Darwin", "macOS", "xattr"}},
		"linux_arm64":  {[]string{"Linux (ARM64)", "aarch64"}, []string{"launchctl", "macOS"}},
	} {
		script := installScript("wss://opamp.example.com/v1/opamp", "", "opamp_k", platform, "0.164.0", nil)
		// Shell variables like ${OS}_${ARCH} are fine; look at what the script literally says.
		for _, w := range tc.want {
			if !strings.Contains(script, w) {
				t.Errorf("%s: script lacks %q", platform, w)
			}
		}
		for _, f := range tc.forbidden {
			if strings.Contains(script, f) {
				t.Errorf("%s: script mentions %q", platform, f)
			}
		}
		// __DIR__ is filled in by the script itself at install time.
		if strings.Contains(strings.ReplaceAll(script, "__DIR__", ""), "__") {
			t.Errorf("%s: unreplaced placeholder", platform)
		}
		path := filepath.Join(t.TempDir(), "install.sh")
		if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
			t.Fatalf("%s: not valid shell: %v\n%s", platform, err, out)
		}
	}
}

func TestEndpointForTransport(t *testing.T) {
	for _, tc := range [][3]string{
		{"wss://opamp.example.com/v1/opamp", "http", "https://opamp.example.com/v1/opamp"},
		{"ws://localhost:4320/v1/opamp", "http", "http://localhost:4320/v1/opamp"},
		{"wss://opamp.example.com/v1/opamp", "websocket", "wss://opamp.example.com/v1/opamp"},
		{"wss://opamp.example.com/v1/opamp", "", "wss://opamp.example.com/v1/opamp"},
		{"https://opamp.example.com/v1/opamp", "http", "https://opamp.example.com/v1/opamp"},
	} {
		if got := endpointFor(tc[0], tc[1]); got != tc[2] {
			t.Errorf("endpointFor(%q, %q) = %q, want %q", tc[0], tc[1], got, tc[2])
		}
	}
	// A plaintext polling endpoint needs the same "insecure" setting as a plaintext WebSocket one.
	if script := installScript("http://localhost:4320/v1/opamp", "", "k", "linux_amd64", "0.164.0", nil); !strings.Contains(script, "endpoint: http://localhost:4320/v1/opamp") || !strings.Contains(script, "insecure: true") {
		t.Error("polling install script lacks the http endpoint or the insecure setting")
	}
}
