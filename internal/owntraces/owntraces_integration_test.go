package owntraces

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/msaif95/opamp-backend/internal/testdb"
)

func TestIntakeKeepsAndForwardsSpans(t *testing.T) {
	_, rdb := testdb.Open(t)
	ctx := context.Background()
	s := New(rdb, []byte("0123456789abcdef0123456789abcdef"), "ws://localhost:4320/v1/opamp")
	s.Redact = func(_ context.Context, _ uuid.UUID, text string) (string, error) {
		return strings.ReplaceAll(text, "s3cr3t-value", "${secret:k}"), nil
	}
	var forwarded [][]byte
	s.Forward = func(_ string, body []byte) { forwarded = append(forwarded, body) }
	uid := uuid.New()
	settings := s.Settings(uid)
	if settings.DestinationEndpoint != "http://localhost:4320/v1/traces" {
		t.Fatalf("endpoint = %s", settings.DestinationEndpoint)
	}
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	raw, _ := proto.Marshal(&collectortrace.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{ScopeSpans: []*tracepb.ScopeSpans{{
		Scope: &commonpb.InstrumentationScope{Name: "otlphttpexporter"},
		Spans: []*tracepb.Span{
			{TraceId: bytes.Repeat([]byte{1}, 16), SpanId: bytes.Repeat([]byte{2}, 8), ParentSpanId: bytes.Repeat([]byte{3}, 8), Name: "exporter/otlphttp/traces",
				Kind: tracepb.Span_SPAN_KIND_CLIENT, StartTimeUnixNano: uint64(start.Add(time.Second).UnixNano()), EndTimeUnixNano: uint64(start.Add(time.Second + 250*time.Millisecond).UnixNano()),
				Status: &tracepb.Status{Code: tracepb.Status_STATUS_CODE_ERROR, Message: "401 with key s3cr3t-value"}},
			{TraceId: bytes.Repeat([]byte{1}, 16), SpanId: bytes.Repeat([]byte{3}, 8), Name: "receiver/otlp/TraceReceived",
				StartTimeUnixNano: uint64(start.UnixNano()), EndTimeUnixNano: uint64(start.Add(2 * time.Second).UnixNano())},
		}}}}}})
	send := func(authz string) int {
		req := httptest.NewRequest(http.MethodPost, IntakePath, bytes.NewReader(raw))
		req.Header.Set("Authorization", authz)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		return w.Code
	}
	if code := send("Bearer " + uuid.NewString() + ".forged"); code != http.StatusUnauthorized || len(forwarded) != 0 {
		t.Fatalf("forged token: HTTP %d, forwarded %d", code, len(forwarded))
	}
	if code := send(settings.Headers.Headers[0].Value); code != http.StatusOK {
		t.Fatalf("intake: HTTP %d", code)
	}
	// Passed on byte for byte.
	if len(forwarded) != 1 || !bytes.Equal(forwarded[0], raw) {
		t.Fatalf("forwarded %d requests", len(forwarded))
	}
	spans, err := s.Recent(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 2 {
		t.Fatalf("spans = %+v", spans)
	}
	got := spans[0] // newest first
	if got.Name != "exporter/otlphttp/traces" || got.Status != "error" || got.DurationMS != 250 || got.Kind != "client" ||
		got.ParentID != spans[1].SpanID || got.Scope != "otlphttpexporter" {
		t.Fatalf("span = %+v", got)
	}
	if strings.Contains(got.StatusMessage, "s3cr3t") {
		t.Fatalf("secret not hidden: %q", got.StatusMessage)
	}
}
