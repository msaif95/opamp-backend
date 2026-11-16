// Command server runs one opamp-backend replica: the OpAMP listener for
// agents and the REST/SSE API for opamp-ui.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/open-telemetry/opamp-go/protobufs"
	"google.golang.org/protobuf/proto"

	"github.com/msaif95/opamp-backend/internal/access"
	"github.com/msaif95/opamp-backend/internal/agentconfig"
	"github.com/msaif95/opamp-backend/internal/alert"
	"github.com/msaif95/opamp-backend/internal/api"
	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/compliance"
	"github.com/msaif95/opamp-backend/internal/config"
	"github.com/msaif95/opamp-backend/internal/connection"
	"github.com/msaif95/opamp-backend/internal/events"
	"github.com/msaif95/opamp-backend/internal/logthrottle"
	"github.com/msaif95/opamp-backend/internal/ownlogs"
	"github.com/msaif95/opamp-backend/internal/owntraces"
	"github.com/msaif95/opamp-backend/internal/pipeline"
	"github.com/msaif95/opamp-backend/internal/protocol"
	"github.com/msaif95/opamp-backend/internal/ratelimit"
	"github.com/msaif95/opamp-backend/internal/registry"
	"github.com/msaif95/opamp-backend/internal/retention"
	"github.com/msaif95/opamp-backend/internal/rollout"
	"github.com/msaif95/opamp-backend/internal/secrets"
	"github.com/msaif95/opamp-backend/internal/settings"
	"github.com/msaif95/opamp-backend/internal/store"
	"github.com/msaif95/opamp-backend/internal/targeting"
	"github.com/msaif95/opamp-backend/internal/telemetry"
	"github.com/msaif95/opamp-backend/internal/throughput"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

// credentialCheckInterval bounds how long a revoked or expired credential
// can keep an already established agent connection open.
const credentialCheckInterval = 30 * time.Second

// redisLogger adapts a function to go-redis's internal logging interface.
type redisLogger func(msg string)

func (f redisLogger) Printf(_ context.Context, format string, v ...any) { f(fmt.Sprintf(format, v...)) }

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})).With("replica", cfg.ReplicaID)
	slog.SetDefault(log)
	log.Info("starting opamp-backend", "version", version)
	if cfg.DevMode {
		log.Warn("DEV_MODE is on: production safety checks are disabled")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Telemetry starts before the database is open, so its switch is bound late.
	var protections atomic.Pointer[settings.Store]
	stopTelemetry, err := telemetry.Setup(ctx, cfg.ReplicaID, func() bool {
		st := protections.Load()
		return st == nil || st.Enabled(settings.Telemetry)
	})
	if err != nil {
		return err
	}
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = stopTelemetry(flushCtx)
	}()
	log.Info("self-telemetry", "otlp_export", telemetry.Enabled())

	if err := store.Migrate(cfg.PostgresDSN, cfg.MigrationsDir); err != nil {
		return err
	}
	db, err := store.Open(ctx, cfg.PostgresDSN, cfg.PostgresMaxConns)
	if err != nil {
		return err
	}
	defer db.Close()

	// go-redis logs every failed dial; during an outage that is thousands of lines a minute.
	redisLog := logthrottle.New(10 * time.Second)
	redis.SetLogger(redisLogger(func(msg string) {
		redisLog.Do(func(suppressed int64) {
			log.Warn("redis client", "msg", msg, "similar_messages_suppressed", suppressed)
		})
	}))
	redisOpts := &redis.Options{Addr: cfg.RedisAddr, DB: cfg.RedisDB, Password: cfg.RedisPassword}
	if cfg.RedisTLS {
		redisOpts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	rdb := redis.NewClient(redisOpts)
	defer rdb.Close()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return err
	}

	reg := registry.New(db, rdb, cfg.ReplicaID, cfg.AgentOfflineAfter)
	agentAuth := auth.NewAgentAuthenticator(db)
	configs := agentconfig.NewService(db)
	tput := throughput.New(rdb, cfg.JWTSigningKey, cfg.AgentEndpointURL)
	handler := protocol.NewHandler(reg, configs, log)
	collectorLogs := ownlogs.New(rdb, cfg.JWTSigningKey, cfg.AgentEndpointURL)
	// One offer covering whichever of its own metrics, logs and traces a
	// collector says it can report. All three come to this backend; traces
	// are also passed on to the tracing backend named in the deployment.
	collectorTraces := owntraces.New(rdb, cfg.JWTSigningKey, cfg.AgentEndpointURL)
	if cfg.OwnTracesEndpoint != "" {
		forwardWarn := logthrottle.New(30 * time.Second)
		client := &http.Client{Timeout: 10 * time.Second}
		slots := make(chan struct{}, 8)
		collectorTraces.Forward = func(encoding string, body []byte) {
			select {
			case slots <- struct{}{}:
			default:
				// The tracing backend is slow or down: drop rather than queue without bound.
				forwardWarn.Do(func(n int64) { log.Warn("own traces not forwarded: too many requests in flight", "similar_dropped", n) })
				return
			}
			go func() {
				defer func() { <-slots }()
				req, err := http.NewRequest(http.MethodPost, cfg.OwnTracesEndpoint, bytes.NewReader(body))
				if err != nil {
					return
				}
				req.Header.Set("Content-Type", "application/x-protobuf")
				if encoding != "" {
					req.Header.Set("Content-Encoding", encoding)
				}
				for name, value := range cfg.OwnTracesHeaders {
					req.Header.Set(name, value)
				}
				resp, err := client.Do(req)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.StatusCode < 300 {
						return
					}
					err = fmt.Errorf("HTTP %d", resp.StatusCode)
				}
				forwardWarn.Do(func(n int64) { log.Warn("own traces not forwarded", "err", err, "similar_errors_suppressed", n) })
			}()
		}
	}
	handler.OwnTelemetry = func(uid uuid.UUID, caps uint64) *protobufs.ConnectionSettingsOffers {
		can := func(c protobufs.AgentCapabilities) bool { return caps&uint64(c) != 0 }
		offer := &protobufs.ConnectionSettingsOffers{}
		if m := tput.Offer(uid); m != nil && can(protobufs.AgentCapabilities_AgentCapabilities_ReportsOwnMetrics) {
			offer.OwnMetrics = m.OwnMetrics
		}
		if can(protobufs.AgentCapabilities_AgentCapabilities_ReportsOwnLogs) {
			offer.OwnLogs = collectorLogs.Settings(uid)
		}
		if can(protobufs.AgentCapabilities_AgentCapabilities_ReportsOwnTraces) {
			offer.OwnTraces = collectorTraces.Settings(uid)
		}
		if offer.OwnMetrics == nil && offer.OwnLogs == nil && offer.OwnTraces == nil {
			return nil
		}
		// The hash lets a collector skip an offer it already applied.
		raw, _ := proto.MarshalOptions{Deterministic: true}.Marshal(offer)
		sum := sha256.Sum256(raw)
		offer.Hash = sum[:]
		return offer
	}
	secretStore, err := secrets.New(db, cfg.SecretsKey)
	if err != nil {
		return err
	}
	handler.ResolveSecrets = func(ctx context.Context, templateID uuid.UUID, body string) (string, error) {
		if len(secrets.References(body)) == 0 {
			return body, nil
		}
		project, err := configs.ProjectOf(ctx, templateID)
		if err != nil {
			return "", err
		}
		return secretStore.Resolve(ctx, project, body)
	}
	if secretStore.Enabled() {
		// A collector may log a header it was sent; hide secret values there too.
		redactFor := func(ctx context.Context, uid uuid.UUID, text string) (string, error) {
			project, err := reg.ProjectOf(ctx, uid)
			if err != nil {
				return "", err
			}
			return secretStore.Redact(ctx, project, text)
		}
		collectorLogs.Redact, collectorTraces.Redact = redactFor, redactFor
		handler.RedactSecrets = func(ctx context.Context, uid uuid.UUID, body string) (string, error) {
			project, err := reg.ProjectOf(ctx, uid)
			if errors.Is(err, registry.ErrNotFound) {
				return body, nil // first contact: nothing has been sent to it yet
			}
			if err != nil {
				return "", err
			}
			return secretStore.Redact(ctx, project, body)
		}
	}
	conns := connection.NewManager(agentAuth, handler, reg, log)
	conns.PendingRestart = reg.TakePendingRestart
	conns.Extra = map[string]http.Handler{throughput.IntakePath: tput, ownlogs.IntakePath: collectorLogs, owntraces.IntakePath: collectorTraces}

	var tlsCfg *tls.Config
	if cfg.TLSCertFile != "" {
		if tlsCfg, err = auth.ServerTLSConfig(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSClientCAFile); err != nil {
			return err
		}
	} else {
		log.Warn("OpAMP listener is plaintext", "tls_terminated_upstream", cfg.AgentTLSUpstream, "dev_mode", cfg.DevMode)
	}
	switches, err := settings.New(ctx, db, rdb, map[string]settings.Definition{
		settings.SSO:        {Available: cfg.OktaIssuer != "", Default: true},
		settings.LocalLogin: {Available: cfg.LocalAdminPassword != "", Default: true},
		// Switching TLS at runtime would drop every agent and, when off, send
		// their credentials in plaintext; it stays a deployment decision.
		settings.StoreEncryption: {Available: cfg.PostgresEncrypted() && cfg.RedisTLS, Default: true, Locked: true},
		settings.AgentTLS:        {Available: tlsCfg != nil || cfg.AgentTLSUpstream, Default: true, Locked: true},
		settings.AgentMTLS:       {Available: cfg.MTLSEnabled(), Default: true},
		settings.AlertDelivery:   {Available: cfg.AlertWebhookURL != "", Default: true},
		settings.Telemetry:       {Available: telemetry.Enabled(), Default: true},
		settings.Rebalancing:     {Available: true, Default: cfg.RebalanceEnabled},
		settings.SecondApprover:  {Available: true, Default: false},
		// Always available: even with no deployment-wide budget, a token can be given its own from the console.
		settings.APIRateLimit:      {Available: true, Default: true},
		settings.FleetHealthAlerts: {Available: cfg.AlertOfflinePct > 0 || cfg.AlertUnhealthyPct > 0, Default: true},
	}, log)
	if err != nil {
		return err
	}
	protections.Store(switches)
	go switches.Run(ctx)
	agentAuth.MTLSEnabled = switches.Func(settings.AgentMTLS)

	if err := conns.Start(cfg.OpAMPListenAddr, tlsCfg); err != nil {
		return err
	}
	log.Info("opamp listener started", "addr", cfg.OpAMPListenAddr, "tls", tlsCfg != nil, "mtls", cfg.MTLSEnabled())

	reg.OnRestart = func(uid uuid.UUID) {
		cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		conns.Restart(cmdCtx, uid)
	}
	go reg.SubscribePush(ctx, func(uid uuid.UUID) {
		pushCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		conns.Push(pushCtx, uid)
	})

	alertStore := alert.NewStore(rdb)
	alerts := alert.NewWebhook(cfg.AlertWebhookURL, log)
	alerts.Enabled = switches.Func(settings.AlertDelivery)
	alerts.Record = func(ctx context.Context, a alert.Alert) {
		if err := alertStore.Add(ctx, a); err != nil {
			log.Error("record alert", "err", err)
		}
	}
	go alerts.Run(ctx)

	startedAt := time.Now().UTC()
	announce := func() {
		if err := reg.AnnounceReplica(ctx, conns.ConnectionCount(), startedAt); err != nil && ctx.Err() == nil {
			log.Error("announce replica", "err", err)
		}
	}
	announce()
	go func() {
		t := time.NewTicker(registry.ReplicaAnnounceInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				announce()
			}
		}
	}()

	rollouts := rollout.NewService(db, reg, log)
	rollouts.OnOutcome = func(_ context.Context, outcome string, r *rollout.Rollout) {
		failed := r.Counts["failed"]
		// A clean completion is not worth a page; everything else is.
		if outcome == "completed" && failed == 0 {
			return
		}
		// For pauses and rollbacks the rollout's own error already says what happened and why.
		what := fmt.Sprintf("completed with %d failed agents", failed)
		if outcome != "completed" && r.Error != nil {
			what = *r.Error
		}
		text := fmt.Sprintf("OpAMP bulk push of %s v%d to %d agents %s.", r.ConfigName, r.ConfigVersion, r.TotalAgents, what)
		if cfg.PublicURL != "" {
			text += " " + cfg.PublicURL + "/rollouts/" + r.ID.String()
		}
		alerts.Notify(text)
	}
	go rollouts.Run(ctx)
	// Fleet trend: one sample a minute, taken by whichever replica wins the minute.
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-tick.C:
				won, err := rdb.SetNX(ctx, "opamp:fleet-sample:"+now.UTC().Format("200601021504"), 1, 2*time.Minute).Result()
				if err != nil || !won {
					continue
				}
				if err := reg.SampleFleet(ctx); err != nil {
					log.Warn("fleet trend sample failed", "err", err)
				}
			}
		}
	}()

	go (&retention.Job{
		DB: db, Redis: rdb, Log: log,
		AuditDays: cfg.AuditRetentionDays, RolloutDays: cfg.RolloutRetentionDays, AgentDays: cfg.AgentRetentionDays, AgentEventDays: cfg.AgentEventRetentionDays,
	}).Run(ctx)

	go (&alert.HealthMonitor{
		Stats: func(ctx context.Context) (alert.FleetStats, error) {
			connected, unhealthy, offline, err := reg.FleetHealth(ctx, alert.RecentlyOfflineWindow)
			return alert.FleetStats{Connected: connected, Unhealthy: unhealthy, RecentlyOffline: offline}, err
		},
		Redis: rdb, Notify: alerts.Notify, OfflinePct: cfg.AlertOfflinePct, UnhealthyPct: cfg.AlertUnhealthyPct,
		PublicURL: cfg.PublicURL, Log: log, Enabled: switches.Func(settings.FleetHealthAlerts),
	}).Run(ctx)

	go (&connection.Rebalancer{
		Manager: conns, ReplicaID: cfg.ReplicaID, StartedAt: startedAt, Replicas: reg.Replicas, Log: log,
		Enabled: switches.Func(settings.Rebalancing),
	}).Run(ctx)

	go func() {
		t := time.NewTicker(credentialCheckInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := conns.EnforceCredentials(ctx); err != nil {
					log.Error("credential enforcement failed", "err", err)
				} else if n > 0 {
					log.Info("closed connections with revoked or expired credentials", "count", n)
				}
			}
		}
	}()

	hub := events.NewHub(log)
	go hub.Run(ctx, rdb, registry.EventsChannel)

	go func() {
		t := time.NewTicker(registry.HeartbeatFlushInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := reg.FlushHeartbeats(ctx); err != nil {
					log.Error("heartbeat flush failed", "err", err)
				}
			}
		}
	}()

	go func() {
		t := time.NewTicker(cfg.AgentOfflineAfter / 3)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := reg.SweepOffline(ctx, cfg.AgentOfflineAfter); err != nil {
					log.Error("offline sweep failed", "err", err)
				} else if n > 0 {
					log.Info("marked stale agents offline", "count", n)
				}
			}
		}
	}()

	projects := access.NewProjects(db)
	apiTokens := auth.NewTokens(db)
	sessions := auth.NewSessions(cfg.JWTSigningKey, cfg.LocalAdminPassword)
	sessions.APITokens = apiTokens.Authenticate
	sessions.Store, sessions.IdleTimeout, sessions.MaxAge = auth.NewRedisSessions(rdb), cfg.SessionIdleTimeout, cfg.SessionMaxAge
	sessionWarn := logthrottle.New(10 * time.Second)
	sessions.OnStoreError = func(err error) {
		sessionWarn.Do(func(suppressed int64) {
			log.Warn("redis unavailable: console sessions cannot be checked for sign-out or idleness", "err", err, "similar_errors_suppressed", suppressed)
		})
	}
	var sso *auth.OIDC
	if cfg.OktaIssuer != "" {
		sso, err = auth.NewOIDC(ctx, auth.OIDCConfig{
			Issuer: cfg.OktaIssuer, ClientID: cfg.OktaClientID, ClientSecret: cfg.OktaClientSecret,
			RedirectURL: cfg.OktaRedirectURL, GroupsClaim: cfg.OktaGroupsClaim,
			AdminGroups: cfg.OktaAdminGroups, OperatorGroups: cfg.OktaOperatorGroups, ViewerGroups: cfg.OktaViewerGroups,
		}, cfg.JWTSigningKey)
		if err != nil {
			return err
		}
		// Someone added to a project may sign in without belonging to a role group.
		sso.IsProjectMember = func(ctx context.Context, subject string) bool {
			ok, err := projects.IsMember(ctx, subject)
			return err == nil && ok
		}
		log.Info("single sign-on enabled", "issuer", cfg.OktaIssuer)
	}

	reports := compliance.NewService(db)
	reports.Notify, reports.PublicURL = alerts.Notify, cfg.PublicURL
	go reports.Run(ctx, log, cfg.ReportRetentionDays)

	limits := ratelimit.New(rdb, cfg.APIRateLimit, cfg.APIRateLimitWrites, log)
	limits.Enabled = switches.Func(settings.APIRateLimit)

	apiSrv := &http.Server{
		Addr: cfg.APIListenAddr,
		Handler: otelhttp.NewHandler((&api.Server{
			DB: db, Registry: reg, Configs: configs, Library: pipeline.NewLibrary(db), Rollouts: rollouts, Agents: agentAuth,
			OIDC: sso, Groups: targeting.NewGroups(db), Events: hub, Log: log,
			Logins: auth.NewLoginLimiter(rdb), TrustProxyHeaders: cfg.TrustProxyHeaders, Limits: limits, Reports: reports,
			Alerts: alertStore, Settings: switches,
			Throughput: tput.Latest, History: tput.History,
			Install: api.InstallConfig{EndpointURL: cfg.AgentEndpointURL, CAFile: cfg.AgentCAFile},
			Status: api.SystemStatus{
				SSOIssuer: cfg.OktaIssuer, Version: version, DevMode: cfg.DevMode,
				AlertOfflinePct: cfg.AlertOfflinePct, AlertUnhealthyPct: cfg.AlertUnhealthyPct,
				AgentOfflineAfterSeconds: int(cfg.AgentOfflineAfter.Seconds()),
				APIRateLimit:             cfg.APIRateLimit, APIRateLimitWrites: cfg.APIRateLimitWrites,
			},
			Logs: collectorLogs.Recent, Traces: collectorTraces.Recent, AllMetrics: tput.All, Sessions: sessions, Tokens: apiTokens, Secrets: secretStore, Projects: projects,
			// Postgres only. A Redis outage degrades pushes and live updates but
			// agents and the console keep working, and marking every replica
			// unready would turn that into a full outage.
			Ready: db.Ping,
		}).Router(), "api"),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No WriteTimeout: the event stream is a long-lived response.
	}
	apiSrv.RegisterOnShutdown(hub.Close)
	apiErr := make(chan error, 1)
	go func() { apiErr <- apiSrv.ListenAndServe() }()
	log.Info("api listener started", "addr", cfg.APIListenAddr)

	select {
	case <-ctx.Done():
	case err := <-apiErr:
		return err
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = reg.WithdrawReplica(shutdownCtx)
	// Agents first, so they move to other replicas while this one drains its API requests.
	return errors.Join(conns.Stop(shutdownCtx), apiSrv.Shutdown(shutdownCtx))
}
