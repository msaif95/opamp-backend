// Package connection hosts the OpAMP listener: it authenticates incoming
// agent connections, tracks live connections on this replica and hands
// messages to the protocol handler.
package connection

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/server"
	"github.com/open-telemetry/opamp-go/server/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/logthrottle"
	"github.com/msaif95/opamp-backend/internal/registry"
)

// OpAMPPath is the HTTP path agents connect to.
const OpAMPPath = "/v1/opamp"

// Authenticator resolves the identity of an incoming agent connection.
type Authenticator interface {
	Authenticate(ctx context.Context, r *http.Request) (registry.Identity, error)
	// Invalid reports which credential IDs and certificate fingerprints have been revoked or have expired.
	Invalid(ctx context.Context, ids []uuid.UUID, fingerprints [][]byte) (map[uuid.UUID]bool, map[string]bool, error)
}

// MessageHandler processes one OpAMP message.
type MessageHandler interface {
	Handle(ctx context.Context, id registry.Identity, msg *protobufs.AgentToServer, needFullState bool) (uuid.UUID, *protobufs.ServerToAgent)
	// Offer returns an unsolicited message for the agent, or nil if there is nothing to send.
	Offer(ctx context.Context, uid uuid.UUID) *protobufs.ServerToAgent
}

// Disconnector is notified when a persistent agent connection closes.
type Disconnector interface {
	Disconnected(ctx context.Context, uid uuid.UUID) error
}

type connState struct {
	uid     uuid.UUID
	id      registry.Identity
	lastSeq uint64
	seen    bool
}

// Manager owns the OpAMP server and the set of live connections on this replica.
type Manager struct {
	auth    Authenticator
	handler MessageHandler
	reg     Disconnector
	log     *slog.Logger

	opamp   server.OpAMPServer
	httpSrv *http.Server

	mu    sync.Mutex
	conns map[types.Connection]*connState
	byUID map[uuid.UUID]types.Connection

	disconnectErr *logthrottle.Throttle
	// Extra handlers served on the agent listener next to the OpAMP endpoint. Set before Start.
	Extra map[string]http.Handler

	messages     metric.Int64Counter
	handleTime   metric.Float64Histogram
	authFailures metric.Int64Counter
	pushes       metric.Int64Counter
	revoked      metric.Int64Counter
	shed         metric.Int64Counter
	tracer       trace.Tracer
}

// NewManager creates a Manager.
func NewManager(auth Authenticator, handler MessageHandler, reg Disconnector, log *slog.Logger) *Manager {
	m := &Manager{
		auth: auth, handler: handler, reg: reg, log: log,
		opamp: server.New(opampLogger{log}),
		conns: make(map[types.Connection]*connState),
		byUID: make(map[uuid.UUID]types.Connection),

		disconnectErr: logthrottle.New(10 * time.Second),
	}
	// Instruments are no-ops unless telemetry.Setup installed a meter provider.
	meter := otel.Meter("github.com/msaif95/opamp-backend/connection")
	m.messages, _ = meter.Int64Counter("opamp.agent.messages", metric.WithDescription("AgentToServer messages handled"))
	m.handleTime, _ = meter.Float64Histogram("opamp.agent.message.duration", metric.WithUnit("s"),
		metric.WithDescription("Time to handle one AgentToServer message"))
	m.authFailures, _ = meter.Int64Counter("opamp.agent.auth.failures", metric.WithDescription("Rejected agent connections"))
	m.pushes, _ = meter.Int64Counter("opamp.agent.pushes", metric.WithDescription("Server-initiated config pushes"))
	m.revoked, _ = meter.Int64Counter("opamp.agent.credential.disconnects",
		metric.WithDescription("Live connections closed because their credential was revoked or expired"))
	m.shed, _ = meter.Int64Counter("opamp.agent.connections.shed",
		metric.WithDescription("Connections closed on purpose so agents reconnect to another replica"))
	m.tracer = otel.Tracer("github.com/msaif95/opamp-backend/connection")
	_, _ = meter.Int64ObservableGauge("opamp.agent.connections", metric.WithDescription("Live WebSocket agent connections on this replica"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			o.Observe(int64(m.ConnectionCount()))
			return nil
		}))
	return m
}

// Start begins serving OpAMP on addr. tlsCfg may be nil for plaintext (dev only).
func (m *Manager) Start(addr string, tlsCfg *tls.Config) error {
	handler, connContext, err := m.opamp.Attach(server.Settings{
		Callbacks:         types.Callbacks{OnConnecting: m.onConnecting},
		EnableCompression: true,
	})
	if err != nil {
		return fmt.Errorf("attach opamp server: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(OpAMPPath, handler)
	for path, h := range m.Extra {
		mux.Handle(path, h)
	}
	m.httpSrv = &http.Server{
		Handler:           mux,
		ConnContext:       connContext,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	go func() {
		var err error
		if tlsCfg != nil {
			err = m.httpSrv.ServeTLS(ln, "", "")
		} else {
			err = m.httpSrv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			m.log.Error("opamp listener stopped", "err", err)
		}
	}()
	return nil
}

// Stop closes the listener and all agent connections. The listener goes
// first: otherwise disconnected agents reconnect straight back to this
// replica, only to be dropped again when the process exits.
func (m *Manager) Stop(ctx context.Context) error {
	var err error
	if m.httpSrv != nil {
		err = m.httpSrv.Shutdown(ctx)
	}
	m.mu.Lock()
	conns := make([]types.Connection, 0, len(m.conns))
	for c := range m.conns {
		conns = append(conns, c)
	}
	m.mu.Unlock()
	for _, c := range conns {
		_ = c.Disconnect()
	}
	return err
}

// ConnectionCount returns the number of live WebSocket connections on this replica.
func (m *Manager) ConnectionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.conns)
}

func (m *Manager) onConnecting(r *http.Request) types.ConnectionResponse {
	id, err := m.auth.Authenticate(r.Context(), r)
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, auth.ErrUnauthenticated) {
			status = http.StatusUnauthorized
			m.authFailures.Add(r.Context(), 1)
		} else {
			m.log.Error("agent authentication error", "remote", r.RemoteAddr, "err", err)
		}
		return types.ConnectionResponse{Accept: false, HTTPStatusCode: status}
	}

	// Plain HTTP polling "closes" after every message, so only WebSocket
	// connections are tracked and trigger a disconnect on close. Polling
	// agents are aged out by the registry's offline sweep.
	persistent := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")

	return types.ConnectionResponse{Accept: true, ConnectionCallbacks: types.ConnectionCallbacks{
		OnConnected: func(_ context.Context, conn types.Connection) {
			if persistent {
				m.mu.Lock()
				m.conns[conn] = &connState{id: id}
				m.mu.Unlock()
			}
		},
		OnMessage: func(ctx context.Context, conn types.Connection, msg *protobufs.AgentToServer) *protobufs.ServerToAgent {
			start := time.Now()
			kind := "state"
			if registry.IsHeartbeat(msg) {
				kind = "heartbeat"
			}
			// Heartbeats are not traced: they are nearly all messages and carry nothing to investigate.
			if kind == "state" {
				var span trace.Span
				ctx, span = m.tracer.Start(ctx, "opamp.agent.message", trace.WithSpanKind(trace.SpanKindServer))
				defer span.End()
			}
			needFull := persistent && m.sequenceGap(conn, msg)
			uid, resp := m.handler.Handle(ctx, id, msg, needFull)
			trace.SpanFromContext(ctx).SetAttributes(attribute.String("opamp.instance_uid", uid.String()))
			attrs := metric.WithAttributes(attribute.String("kind", kind))
			m.messages.Add(ctx, 1, attrs)
			m.handleTime.Record(ctx, time.Since(start).Seconds(), attrs)
			if persistent && uid != uuid.Nil {
				m.mu.Lock()
				if st := m.conns[conn]; st != nil {
					st.uid = uid
					m.byUID[uid] = conn
				}
				m.mu.Unlock()
			}
			return resp
		},
		OnConnectionClose: func(conn types.Connection) {
			if !persistent {
				return
			}
			m.mu.Lock()
			st := m.conns[conn]
			delete(m.conns, conn)
			// The agent may already have reconnected on a newer connection.
			if st != nil && m.byUID[st.uid] == conn {
				delete(m.byUID, st.uid)
			}
			m.mu.Unlock()
			if st == nil || st.uid == uuid.Nil {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := m.reg.Disconnected(ctx, st.uid); err != nil {
				m.disconnectErr.Do(func(suppressed int64) {
					m.log.Error("mark agent disconnected", "instance_uid", st.uid, "err", err, "similar_errors_suppressed", suppressed)
				})
			}
		},
	}}
}

// Push sends the agent its pending server-initiated message (currently its
// desired remote config), if it is connected to this replica over WebSocket.
func (m *Manager) Push(ctx context.Context, uid uuid.UUID) {
	m.mu.Lock()
	conn := m.byUID[uid]
	m.mu.Unlock()
	if conn == nil {
		return
	}
	ctx, span := m.tracer.Start(ctx, "opamp.agent.push", trace.WithAttributes(attribute.String("opamp.instance_uid", uid.String())))
	defer span.End()
	msg := m.handler.Offer(ctx, uid)
	if msg == nil {
		return
	}
	result := "sent"
	if err := conn.Send(ctx, msg); err != nil {
		// Not fatal: the config is offered again on the agent's next message.
		m.log.WarnContext(ctx, "push to agent failed", "instance_uid", uid, "err", err)
		result = "failed"
	}
	m.pushes.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
}

// EnforceCredentials closes live connections whose credential was revoked
// or has expired since they connected. Authentication only happens at
// connect time, so without this a revoked agent would stay connected until
// it next reconnected. It returns the number of connections closed.
func (m *Manager) EnforceCredentials(ctx context.Context) (int, error) {
	m.mu.Lock()
	idSet, fpSet := map[uuid.UUID]struct{}{}, map[string]struct{}{}
	for _, st := range m.conns {
		if st.id.CredentialID != nil {
			idSet[*st.id.CredentialID] = struct{}{}
		}
		if st.id.CertFingerprint != nil {
			fpSet[string(st.id.CertFingerprint)] = struct{}{}
		}
	}
	m.mu.Unlock()
	if len(idSet)+len(fpSet) == 0 {
		return 0, nil
	}
	ids := make([]uuid.UUID, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}
	fps := make([][]byte, 0, len(fpSet))
	for fp := range fpSet {
		fps = append(fps, []byte(fp))
	}
	badIDs, badCerts, err := m.auth.Invalid(ctx, ids, fps)
	if err != nil {
		return 0, err
	}

	now := time.Now()
	var drop []types.Connection
	m.mu.Lock()
	for conn, st := range m.conns {
		switch {
		case st.id.CredentialID != nil && badIDs[*st.id.CredentialID],
			st.id.CertFingerprint != nil && badCerts[string(st.id.CertFingerprint)],
			!st.id.CertNotAfter.IsZero() && now.After(st.id.CertNotAfter):
			drop = append(drop, conn)
		}
	}
	m.mu.Unlock()
	for _, conn := range drop {
		_ = conn.Disconnect()
	}
	m.revoked.Add(ctx, int64(len(drop)))
	return len(drop), nil
}

// sequenceGap records the message's sequence number and reports whether the
// server may have missed state: a gap in sequence numbers, or a first
// message on the connection that carries no agent description.
func (m *Manager) sequenceGap(conn types.Connection, msg *protobufs.AgentToServer) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.conns[conn]
	if st == nil {
		return false
	}
	gap := msg.AgentDescription == nil && (!st.seen || msg.SequenceNum != st.lastSeq+1)
	st.seen, st.lastSeq = true, msg.SequenceNum
	return gap
}

type opampLogger struct{ log *slog.Logger }

func (l opampLogger) Debugf(ctx context.Context, format string, v ...any) {
	l.log.DebugContext(ctx, fmt.Sprintf(format, v...))
}

func (l opampLogger) Errorf(ctx context.Context, format string, v ...any) {
	l.log.ErrorContext(ctx, fmt.Sprintf(format, v...))
}
