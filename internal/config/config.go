// Package config loads opamp-backend runtime configuration from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the full runtime configuration for one backend replica.
type Config struct {
	// ReplicaID uniquely identifies this backend instance in the Redis routing table.
	ReplicaID string

	OpAMPListenAddr string
	APIListenAddr   string

	// TLS for the OpAMP listener. CertFile/KeyFile are the server identity
	// (issued by cert-manager). ClientCAFile is the CA bundle used to verify
	// agent client certs for mTLS mode. If ClientCAFile is empty, mTLS is
	// disabled and only API-key auth is accepted.
	TLSCertFile     string
	TLSKeyFile      string
	TLSClientCAFile string

	PostgresDSN string
	// PostgresMaxConns caps this replica's connection pool. Size it so that
	// replicas x PostgresMaxConns stays below the server's max_connections.
	PostgresMaxConns int
	RedisAddr        string
	RedisDB          int

	// JWTSigningKey signs human-session JWTs and agent JWTs.
	JWTSigningKey []byte
	// LocalAdminPassword enables the break-glass local admin login when set.
	LocalAdminPassword string

	// Okta OIDC (optional; disabled if issuer empty).
	OktaIssuer       string
	OktaClientID     string
	OktaClientSecret string
	OktaRedirectURL  string
	// OktaGroupsClaim is the ID token claim listing the user's groups.
	OktaGroupsClaim string
	// Okta groups granting each role (comma-separated in the environment).
	OktaAdminGroups    []string
	OktaOperatorGroups []string
	OktaViewerGroups   []string

	// AgentOfflineAfter is how long without a heartbeat before an agent is marked offline.
	AgentOfflineAfter time.Duration

	// AlertWebhookURL receives rollout notifications as {"text": ...}
	// (Slack-compatible). Empty disables alerting.
	AlertWebhookURL string
	// PublicURL is the console's base URL, used for links in notifications.
	PublicURL string
	// RebalanceEnabled lets an overloaded replica close some agent
	// connections so they reconnect to less loaded replicas.
	RebalanceEnabled bool
	// Fleet-health alert thresholds, in percent; 0 disables the rule.
	AlertOfflinePct   float64
	AlertUnhealthyPct float64
	// TrustProxyHeaders takes client addresses from X-Forwarded-For.
	TrustProxyHeaders bool

	MigrationsDir string
	LogLevel      string
}

// Load reads configuration from environment variables, applying dev-friendly defaults.
func Load() (*Config, error) {
	host, _ := os.Hostname()
	c := &Config{
		ReplicaID:          env("OPAMP_REPLICA_ID", host),
		OpAMPListenAddr:    env("OPAMP_LISTEN_ADDR", ":4320"),
		APIListenAddr:      env("API_LISTEN_ADDR", ":8080"),
		TLSCertFile:        env("TLS_CERT_FILE", ""),
		TLSKeyFile:         env("TLS_KEY_FILE", ""),
		TLSClientCAFile:    env("TLS_CLIENT_CA_FILE", ""),
		PostgresDSN:        env("POSTGRES_DSN", "postgres://opamp:opamp@localhost:5432/opamp?sslmode=disable"),
		RedisAddr:          env("REDIS_ADDR", "localhost:6379"),
		JWTSigningKey:      []byte(env("JWT_SIGNING_KEY", "")),
		LocalAdminPassword: env("LOCAL_ADMIN_PASSWORD", ""),
		OktaIssuer:         env("OKTA_ISSUER", ""),
		OktaClientID:       env("OKTA_CLIENT_ID", ""),
		OktaClientSecret:   env("OKTA_CLIENT_SECRET", ""),
		OktaRedirectURL:    env("OKTA_REDIRECT_URL", ""),
		OktaGroupsClaim:    env("OKTA_GROUPS_CLAIM", "groups"),
		OktaAdminGroups:    list(env("OKTA_ADMIN_GROUPS", "")),
		OktaOperatorGroups: list(env("OKTA_OPERATOR_GROUPS", "")),
		OktaViewerGroups:   list(env("OKTA_VIEWER_GROUPS", "")),
		AlertWebhookURL:    env("ALERT_WEBHOOK_URL", ""),
		PublicURL:          strings.TrimRight(env("PUBLIC_URL", ""), "/"),
		RebalanceEnabled:   env("REBALANCE_ENABLED", "true") == "true",
		TrustProxyHeaders:  env("TRUST_PROXY_HEADERS", "false") == "true",
		MigrationsDir:      env("MIGRATIONS_DIR", "migrations"),
		LogLevel:           env("LOG_LEVEL", "info"),
	}

	var err error
	if c.PostgresMaxConns, err = strconv.Atoi(env("POSTGRES_MAX_CONNS", "10")); err != nil || c.PostgresMaxConns < 2 {
		return nil, fmt.Errorf("POSTGRES_MAX_CONNS must be a number of at least 2")
	}
	if c.AlertOfflinePct, err = strconv.ParseFloat(env("ALERT_OFFLINE_PCT", "10"), 64); err != nil || c.AlertOfflinePct < 0 || c.AlertOfflinePct > 100 {
		return nil, fmt.Errorf("ALERT_OFFLINE_PCT must be a percentage between 0 and 100")
	}
	if c.AlertUnhealthyPct, err = strconv.ParseFloat(env("ALERT_UNHEALTHY_PCT", "20"), 64); err != nil || c.AlertUnhealthyPct < 0 || c.AlertUnhealthyPct > 100 {
		return nil, fmt.Errorf("ALERT_UNHEALTHY_PCT must be a percentage between 0 and 100")
	}
	if c.RedisDB, err = strconv.Atoi(env("REDIS_DB", "0")); err != nil {
		return nil, fmt.Errorf("REDIS_DB: %w", err)
	}
	if c.AgentOfflineAfter, err = time.ParseDuration(env("AGENT_OFFLINE_AFTER", "90s")); err != nil {
		return nil, fmt.Errorf("AGENT_OFFLINE_AFTER: %w", err)
	}
	if len(c.JWTSigningKey) < 32 {
		return nil, fmt.Errorf("JWT_SIGNING_KEY must be set and at least 32 bytes")
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return nil, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	}
	if c.TLSClientCAFile != "" && c.TLSCertFile == "" {
		return nil, fmt.Errorf("TLS_CLIENT_CA_FILE requires TLS_CERT_FILE/TLS_KEY_FILE")
	}
	return c, nil
}

// MTLSEnabled reports whether agent client-cert verification is configured.
func (c *Config) MTLSEnabled() bool { return c.TLSClientCAFile != "" }

// list splits a comma-separated value, dropping blanks.
func list(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
