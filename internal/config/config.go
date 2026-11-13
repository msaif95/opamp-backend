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
	// DevMode relaxes the production safety checks in Validate: plaintext
	// agent connections and weak secrets are allowed. Never set it in production.
	DevMode bool
	// AgentTLSUpstream declares that a load balancer in front of the OpAMP
	// port terminates TLS, so the listener itself may be plaintext. Agent
	// client certificates (mTLS) cannot be used in that setup.
	AgentTLSUpstream bool

	// Retention, in days; 0 keeps the data forever.
	AuditRetentionDays   int
	RolloutRetentionDays int
	// SessionIdleTimeout signs a console user out after this long without
	// activity; SessionMaxAge signs them out regardless.
	SessionIdleTimeout time.Duration
	SessionMaxAge      time.Duration
	// AgentRetentionDays removes agents that have been offline this long.
	AgentRetentionDays int
	// AgentEventRetentionDays bounds each agent's history.
	AgentEventRetentionDays int

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
	// RedisTLS encrypts the Redis connection; RedisPassword authenticates it.
	RedisTLS      bool
	RedisPassword string
	// AllowUnencryptedStores accepts Postgres or Redis without TLS outside dev
	// mode, for clusters where a service mesh already encrypts that traffic.
	AllowUnencryptedStores bool
	RedisDB                int

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
	// AgentEndpointURL is the OpAMP URL collectors use to reach this
	// deployment from outside, e.g. wss://opamp-agents.example.com/v1/opamp.
	// It is written into generated install commands.
	AgentEndpointURL string
	// AgentCAFile is the CA collectors must trust to verify that endpoint;
	// defaults to TLSClientCAFile, which holds the same CA in the Helm chart.
	AgentCAFile string
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
		ReplicaID:              env("OPAMP_REPLICA_ID", host),
		OpAMPListenAddr:        env("OPAMP_LISTEN_ADDR", ":4320"),
		APIListenAddr:          env("API_LISTEN_ADDR", ":8080"),
		TLSCertFile:            env("TLS_CERT_FILE", ""),
		TLSKeyFile:             env("TLS_KEY_FILE", ""),
		TLSClientCAFile:        env("TLS_CLIENT_CA_FILE", ""),
		PostgresDSN:            env("POSTGRES_DSN", "postgres://opamp:opamp@localhost:5432/opamp?sslmode=disable"),
		RedisAddr:              env("REDIS_ADDR", "localhost:6379"),
		RedisTLS:               env("REDIS_TLS", "false") == "true",
		RedisPassword:          env("REDIS_PASSWORD", ""),
		AllowUnencryptedStores: env("ALLOW_UNENCRYPTED_STORES", "false") == "true",
		JWTSigningKey:          []byte(env("JWT_SIGNING_KEY", "")),
		LocalAdminPassword:     env("LOCAL_ADMIN_PASSWORD", ""),
		OktaIssuer:             env("OKTA_ISSUER", ""),
		OktaClientID:           env("OKTA_CLIENT_ID", ""),
		OktaClientSecret:       env("OKTA_CLIENT_SECRET", ""),
		OktaRedirectURL:        env("OKTA_REDIRECT_URL", ""),
		OktaGroupsClaim:        env("OKTA_GROUPS_CLAIM", "groups"),
		OktaAdminGroups:        list(env("OKTA_ADMIN_GROUPS", "")),
		OktaOperatorGroups:     list(env("OKTA_OPERATOR_GROUPS", "")),
		OktaViewerGroups:       list(env("OKTA_VIEWER_GROUPS", "")),
		AlertWebhookURL:        env("ALERT_WEBHOOK_URL", ""),
		PublicURL:              strings.TrimRight(env("PUBLIC_URL", ""), "/"),
		AgentEndpointURL:       env("AGENT_ENDPOINT_URL", ""),
		AgentCAFile:            env("AGENT_CA_FILE", env("TLS_CLIENT_CA_FILE", "")),
		RebalanceEnabled:       env("REBALANCE_ENABLED", "true") == "true",
		TrustProxyHeaders:      env("TRUST_PROXY_HEADERS", "false") == "true",
		DevMode:                env("DEV_MODE", "false") == "true",
		AgentTLSUpstream:       env("AGENT_TLS_TERMINATED_UPSTREAM", "false") == "true",
		MigrationsDir:          env("MIGRATIONS_DIR", "migrations"),
		LogLevel:               env("LOG_LEVEL", "info"),
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
	if c.SessionIdleTimeout, err = time.ParseDuration(env("SESSION_IDLE_TIMEOUT", "30m")); err != nil || c.SessionIdleTimeout < time.Minute {
		return nil, fmt.Errorf("SESSION_IDLE_TIMEOUT must be a duration of at least 1m")
	}
	if c.SessionMaxAge, err = time.ParseDuration(env("SESSION_MAX_AGE", "8h")); err != nil || c.SessionMaxAge < c.SessionIdleTimeout || c.SessionMaxAge > 24*time.Hour {
		return nil, fmt.Errorf("SESSION_MAX_AGE must be a duration between SESSION_IDLE_TIMEOUT and 24h")
	}
	for name, dst := range map[string]*int{
		"AUDIT_RETENTION_DAYS": &c.AuditRetentionDays, "ROLLOUT_RETENTION_DAYS": &c.RolloutRetentionDays,
		"AGENT_RETENTION_DAYS": &c.AgentRetentionDays, "AGENT_EVENT_RETENTION_DAYS": &c.AgentEventRetentionDays,
	} {
		def := map[string]string{"AUDIT_RETENTION_DAYS": "0", "ROLLOUT_RETENTION_DAYS": "180", "AGENT_RETENTION_DAYS": "30", "AGENT_EVENT_RETENTION_DAYS": "90"}[name]
		if *dst, err = strconv.Atoi(env(name, def)); err != nil || *dst < 0 {
			return nil, fmt.Errorf("%s must be a number of days, 0 or more", name)
		}
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
	if c.AgentEndpointURL == "" && c.DevMode {
		c.AgentEndpointURL = "ws://localhost" + c.OpAMPListenAddr + "/v1/opamp"
	}
	if c.AgentEndpointURL != "" && !strings.HasPrefix(c.AgentEndpointURL, "ws://") && !strings.HasPrefix(c.AgentEndpointURL, "wss://") {
		return nil, fmt.Errorf("AGENT_ENDPOINT_URL must start with ws:// or wss://")
	}
	return c, c.validateProduction()
}

// validateProduction refuses configurations that are only safe on a
// developer's machine, unless DevMode says that is where we are. Failing at
// start-up beats discovering a plaintext listener or a default password in
// production.
func (c *Config) validateProduction() error {
	if c.DevMode {
		return nil
	}
	var problems []string
	if c.TLSCertFile == "" && !c.AgentTLSUpstream {
		problems = append(problems, "agent connections would be plaintext: set TLS_CERT_FILE and TLS_KEY_FILE, "+
			"or AGENT_TLS_TERMINATED_UPSTREAM=true if a load balancer terminates TLS")
	}
	if !c.AllowUnencryptedStores {
		if !c.PostgresEncrypted() {
			problems = append(problems, "the Postgres connection is not encrypted: use sslmode=require or stricter in POSTGRES_DSN")
		}
		if !c.RedisTLS {
			problems = append(problems, "the Redis connection is not encrypted: set REDIS_TLS=true")
		}
		if !c.PostgresEncrypted() || !c.RedisTLS {
			problems = append(problems, "(set ALLOW_UNENCRYPTED_STORES=true only if the network path to the stores is encrypted another way)")
		}
	}
	if strings.Contains(strings.ToLower(string(c.JWTSigningKey)), "dev-only") {
		problems = append(problems, "JWT_SIGNING_KEY is the development key")
	}
	if c.LocalAdminPassword != "" && len(c.LocalAdminPassword) < minAdminPasswordLen {
		problems = append(problems, fmt.Sprintf("LOCAL_ADMIN_PASSWORD is shorter than %d characters", minAdminPasswordLen))
	}
	if strings.HasPrefix(c.AgentEndpointURL, "ws://") {
		problems = append(problems, "AGENT_ENDPOINT_URL must use wss")
	}
	if c.OktaIssuer != "" && !strings.HasPrefix(c.OktaIssuer, "https://") {
		problems = append(problems, "OKTA_ISSUER must use https")
	}
	if c.OktaIssuer != "" && !strings.HasPrefix(c.OktaRedirectURL, "https://") {
		problems = append(problems, "OKTA_REDIRECT_URL must use https")
	}
	if c.OktaIssuer == "" && c.LocalAdminPassword == "" {
		problems = append(problems, "no sign-in method: configure Okta or set LOCAL_ADMIN_PASSWORD")
	}
	if len(problems) > 0 {
		return fmt.Errorf("unsafe configuration (set DEV_MODE=true only on a development machine): %s", strings.Join(problems, "; "))
	}
	return nil
}

const minAdminPasswordLen = 16

// PostgresEncrypted reports whether the DSN demands TLS to the database.
func (c *Config) PostgresEncrypted() bool {
	for _, mode := range []string{"sslmode=require", "sslmode=verify-ca", "sslmode=verify-full"} {
		if strings.Contains(c.PostgresDSN, mode) {
			return true
		}
	}
	return false
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
