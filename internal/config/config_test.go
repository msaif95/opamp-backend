package config

import (
	"strings"
	"testing"
)

const strongKey = "k3y-with-plenty-of-entropy-0123456789abcdef"

func TestProductionGuards(t *testing.T) {
	base := map[string]string{
		"JWT_SIGNING_KEY": strongKey, "LOCAL_ADMIN_PASSWORD": "a-long-break-glass-password",
		"TLS_CERT_FILE": "/tls/tls.crt", "TLS_KEY_FILE": "/tls/tls.key",
		"POSTGRES_DSN": "postgres://u:p@db/opamp?sslmode=verify-full", "REDIS_TLS": "true",
	}
	for name, tc := range map[string]struct {
		set     map[string]string
		wantErr string // substring; "" means the config is accepted
	}{
		"production baseline":           {nil, ""},
		"plaintext agents":              {map[string]string{"TLS_CERT_FILE": "", "TLS_KEY_FILE": ""}, "plaintext"},
		"plaintext behind a TLS proxy":  {map[string]string{"TLS_CERT_FILE": "", "TLS_KEY_FILE": "", "AGENT_TLS_TERMINATED_UPSTREAM": "true"}, ""},
		"development signing key":       {map[string]string{"JWT_SIGNING_KEY": "dev-only-signing-key-do-not-use-in-prod"}, "development key"},
		"short admin password":          {map[string]string{"LOCAL_ADMIN_PASSWORD": "admin"}, "shorter than"},
		"okta over http":                {map[string]string{"OKTA_ISSUER": "http://idp", "OKTA_REDIRECT_URL": "https://c/cb"}, "OKTA_ISSUER must use https"},
		"okta redirect over http":       {map[string]string{"OKTA_ISSUER": "https://idp", "OKTA_REDIRECT_URL": "http://c/cb"}, "OKTA_REDIRECT_URL must use https"},
		"nobody can sign in":            {map[string]string{"LOCAL_ADMIN_PASSWORD": ""}, "no sign-in method"},
		"dev mode allows all of it":     {map[string]string{"DEV_MODE": "true", "TLS_CERT_FILE": "", "TLS_KEY_FILE": "", "LOCAL_ADMIN_PASSWORD": "admin", "JWT_SIGNING_KEY": "dev-only-signing-key-do-not-use-in-prod"}, ""},
		"short signing key even in dev": {map[string]string{"DEV_MODE": "true", "JWT_SIGNING_KEY": "short"}, "at least 32 bytes"},
		"development secrets key":       {map[string]string{"SECRETS_ENCRYPTION_KEY": "dev-only-secrets-key-do-not-use-in-prod"}, "SECRETS_ENCRYPTION_KEY is the development key"},
		"postgres without tls":          {map[string]string{"POSTGRES_DSN": "postgres://u:p@db/opamp?sslmode=disable"}, "Postgres connection is not encrypted"},
		"redis without tls":             {map[string]string{"REDIS_TLS": "false"}, "Redis connection is not encrypted"},
		"stores encrypted by a mesh":    {map[string]string{"REDIS_TLS": "false", "POSTGRES_DSN": "postgres://u:p@db/opamp", "ALLOW_UNENCRYPTED_STORES": "true"}, ""},
		"negative retention":            {map[string]string{"AUDIT_RETENTION_DAYS": "-1"}, "AUDIT_RETENTION_DAYS"},
	} {
		t.Run(name, func(t *testing.T) {
			for _, k := range []string{"SECRETS_ENCRYPTION_KEY", "ALLOW_UNENCRYPTED_STORES", "DEV_MODE", "AGENT_TLS_TERMINATED_UPSTREAM", "OKTA_ISSUER", "OKTA_REDIRECT_URL", "AUDIT_RETENTION_DAYS", "TLS_CLIENT_CA_FILE"} {
				t.Setenv(k, "")
			}
			t.Setenv("DEV_MODE", "false")
			t.Setenv("AGENT_TLS_TERMINATED_UPSTREAM", "false")
			t.Setenv("AUDIT_RETENTION_DAYS", "0")
			for k, v := range base {
				t.Setenv(k, v)
			}
			for k, v := range tc.set {
				t.Setenv(k, v)
			}
			_, err := Load()
			if tc.wantErr == "" && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}
