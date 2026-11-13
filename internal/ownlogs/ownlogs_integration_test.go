package ownlogs

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"

	"github.com/msaif95/opamp-backend/internal/testdb"
)

func str(s string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: s}}
}

func TestIntakeKeepsRecentLines(t *testing.T) {
	_, rdb := testdb.Open(t)
	ctx := context.Background()
	s := New(rdb, []byte("0123456789abcdef0123456789abcdef"), "wss://opamp.example.com/v1/opamp")
	s.Redact = func(_ context.Context, _ uuid.UUID, text string) (string, error) {
		return strings.ReplaceAll(text, "s3cr3t-value", "${secret:k}"), nil
	}
	uid := uuid.New()
	settings := s.Settings(uid)
	if settings.DestinationEndpoint != "https://opamp.example.com/v1/logs" {
		t.Fatalf("endpoint = %s", settings.DestinationEndpoint)
	}
	auth := settings.Headers.Headers[0].Value

	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	rec := func(offset time.Duration, sev logspb.SeverityNumber, msg string) *logspb.LogRecord {
		return &logspb.LogRecord{TimeUnixNano: uint64(base.Add(offset).UnixNano()), SeverityNumber: sev, Body: str(msg),
			Attributes: []*commonpb.KeyValue{{Key: "otelcol.component.id", Value: str("otlphttp")}}}
	}
	send := func(authz string, gz bool, records ...*logspb.LogRecord) int {
		t.Helper()
		raw, _ := proto.Marshal(&collectorlogs.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{ScopeLogs: []*logspb.ScopeLogs{{LogRecords: records}}}}})
		var body bytes.Buffer
		if gz {
			zw := gzip.NewWriter(&body)
			_, _ = zw.Write(raw)
			_ = zw.Close()
		} else {
			body.Write(raw)
		}
		req := httptest.NewRequest(http.MethodPost, IntakePath, &body)
		req.Header.Set("Authorization", authz)
		if gz {
			req.Header.Set("Content-Encoding", "gzip")
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		return w.Code
	}

	if code := send("Bearer "+uuid.NewString()+".forged", false, rec(0, logspb.SeverityNumber_SEVERITY_NUMBER_INFO, "x")); code != http.StatusUnauthorized {
		t.Fatalf("forged token: HTTP %d", code)
	}
	// Out of order within a request, gzip-compressed, with a secret in one line.
	if code := send(auth, true,
		rec(2*time.Second, logspb.SeverityNumber_SEVERITY_NUMBER_ERROR, "export failed: header api-key=s3cr3t-value rejected"),
		rec(1*time.Second, logspb.SeverityNumber_SEVERITY_NUMBER_INFO, "Everything is ready")); code != http.StatusOK {
		t.Fatalf("intake: HTTP %d", code)
	}
	lines, err := s.Recent(ctx, uid, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0].Severity != "error" || lines[1].Message != "Everything is ready" || lines[0].Attributes["otelcol.component.id"] != "otlphttp" {
		t.Fatalf("lines (newest first) = %+v", lines)
	}
	if strings.Contains(lines[0].Message, "s3cr3t") || !strings.Contains(lines[0].Message, "${secret:k}") {
		t.Fatalf("secret not hidden: %q", lines[0].Message)
	}
	// Another collector sees nothing, and only the newest lines are kept.
	if other, _ := s.Recent(ctx, uuid.New(), 0); len(other) != 0 {
		t.Fatalf("another collector's lines: %+v", other)
	}
	var many []*logspb.LogRecord
	for i := 0; i < Keep+50; i++ {
		many = append(many, rec(time.Duration(10+i)*time.Second, logspb.SeverityNumber_SEVERITY_NUMBER_WARN, "tick"))
	}
	if code := send(auth, false, many...); code != http.StatusOK {
		t.Fatalf("intake: HTTP %d", code)
	}
	if lines, _ = s.Recent(ctx, uid, 0); len(lines) != Keep || lines[0].Severity != "warn" {
		t.Fatalf("kept %d lines, newest %+v", len(lines), lines[0])
	}
}
