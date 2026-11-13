// Command server runs one opamp-backend replica: the OpAMP listener for
// agents and the REST/SSE API for opamp-ui.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/msaif95/opamp-backend/internal/agentconfig"
	"github.com/msaif95/opamp-backend/internal/api"
	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/config"
	"github.com/msaif95/opamp-backend/internal/connection"
	"github.com/msaif95/opamp-backend/internal/events"
	"github.com/msaif95/opamp-backend/internal/protocol"
	"github.com/msaif95/opamp-backend/internal/registry"
	"github.com/msaif95/opamp-backend/internal/rollout"
	"github.com/msaif95/opamp-backend/internal/store"
	"github.com/msaif95/opamp-backend/internal/targeting"
)

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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := store.Migrate(cfg.PostgresDSN, cfg.MigrationsDir); err != nil {
		return err
	}
	db, err := store.Open(ctx, cfg.PostgresDSN)
	if err != nil {
		return err
	}
	defer db.Close()

	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr, DB: cfg.RedisDB})
	defer rdb.Close()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return err
	}

	reg := registry.New(db, rdb, cfg.ReplicaID, cfg.AgentOfflineAfter)
	agentAuth := auth.NewAgentAuthenticator(db)
	configs := agentconfig.NewService(db)
	conns := connection.NewManager(agentAuth, protocol.NewHandler(reg, configs, log), reg, log)

	var tlsCfg *tls.Config
	if cfg.TLSCertFile != "" {
		if tlsCfg, err = auth.ServerTLSConfig(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSClientCAFile); err != nil {
			return err
		}
	} else {
		log.Warn("OpAMP listener running WITHOUT TLS; development use only")
	}
	if err := conns.Start(cfg.OpAMPListenAddr, tlsCfg); err != nil {
		return err
	}
	log.Info("opamp listener started", "addr", cfg.OpAMPListenAddr, "tls", tlsCfg != nil, "mtls", cfg.MTLSEnabled())

	go reg.SubscribePush(ctx, func(uid uuid.UUID) {
		pushCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		conns.Push(pushCtx, uid)
	})

	rollouts := rollout.NewService(db, reg, log)
	go rollouts.Run(ctx)

	hub := events.NewHub(log)
	go hub.Run(ctx, rdb, registry.EventsChannel)

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
		log.Info("single sign-on enabled", "issuer", cfg.OktaIssuer)
	}

	apiSrv := &http.Server{
		Addr: cfg.APIListenAddr,
		Handler: (&api.Server{
			DB: db, Registry: reg, Configs: configs, Rollouts: rollouts, Agents: agentAuth,
			OIDC: sso, Groups: targeting.NewGroups(db), Events: hub, Log: log,
			Sessions: auth.NewSessions(cfg.JWTSigningKey, cfg.LocalAdminPassword),
			Ready: func(ctx context.Context) error {
				return errors.Join(db.Ping(ctx), rdb.Ping(ctx).Err())
			},
		}).Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}
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
	return errors.Join(apiSrv.Shutdown(shutdownCtx), conns.Stop(shutdownCtx))
}
