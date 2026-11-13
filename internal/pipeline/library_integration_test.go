package pipeline_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/msaif95/opamp-backend/internal/agentconfig"
	"github.com/msaif95/opamp-backend/internal/pipeline"
	"github.com/msaif95/opamp-backend/internal/testdb"
)

func TestLibrary(t *testing.T) {
	db, _ := testdb.Open(t)
	ctx := context.Background()
	lib := pipeline.NewLibrary(db)

	if _, issues, _ := lib.Save(ctx, nil, pipeline.KindDestination, "gw", "otlp_grpc", map[string]any{}, "alice"); len(issues) == 0 {
		t.Fatal("item with a missing required setting was accepted")
	}
	if _, issues, _ := lib.Save(ctx, nil, pipeline.KindDestination, "gw", "nope", nil, "alice"); len(issues) == 0 {
		t.Fatal("unknown type accepted")
	}
	gw, issues, err := lib.Save(ctx, nil, pipeline.KindDestination, "gw", "otlp_grpc", map[string]any{"endpoint": "old:4317"}, "alice")
	if err != nil || len(issues) != 0 {
		t.Fatalf("save: %v %+v", err, issues)
	}
	if _, _, err := lib.Save(ctx, nil, pipeline.KindDestination, "gw", "otlp_grpc", map[string]any{"endpoint": "x:1"}, "alice"); !errors.Is(err, pipeline.ErrLibraryNameTaken) {
		t.Fatalf("duplicate name: %v", err)
	}

	spec := pipeline.Spec{
		Sources:      []pipeline.Component{{Type: "otlp"}},
		Destinations: []pipeline.Component{{Library: &gw.ID}},
	}
	render := func() string {
		t.Helper()
		resolved, issues, err := lib.Resolve(ctx, spec)
		if err != nil || len(issues) != 0 {
			t.Fatalf("resolve: %v %+v", err, issues)
		}
		body, issues := pipeline.Render(resolved)
		if agentconfig.HasErrors(issues) {
			t.Fatalf("render: %+v", issues)
		}
		return body
	}
	if !strings.Contains(render(), "old:4317") {
		t.Fatal("library settings not used")
	}
	// Resolve must not write into the caller's spec: the stored spec keeps only the reference.
	if spec.Destinations[0].Type != "" {
		t.Fatal("Resolve modified the original spec")
	}

	// Changing the item changes what the same pipeline renders next time.
	if _, _, err := lib.Save(ctx, &gw.ID, pipeline.KindDestination, "gateway", "otlp_grpc", map[string]any{"endpoint": "new:4317"}, "bob"); err != nil {
		t.Fatal(err)
	}
	if body := render(); !strings.Contains(body, "new:4317") || strings.Contains(body, "old:4317") {
		t.Fatal("updated library settings not used")
	}
	// Type cannot change under configs that use the item.
	if _, _, err := lib.Save(ctx, &gw.ID, pipeline.KindDestination, "gateway", "otlp_http", map[string]any{"endpoint": "https://x"}, "bob"); !errors.Is(err, pipeline.ErrLibraryNotFound) {
		t.Fatalf("type change: %v", err)
	}

	// A source item cannot be used as a destination, and a deleted item is reported.
	src, _, _ := lib.Save(ctx, nil, pipeline.KindSource, "in", "otlp", nil, "alice")
	wrong := pipeline.Spec{Sources: []pipeline.Component{{Type: "otlp"}}, Destinations: []pipeline.Component{{Library: &src.ID}}}
	if _, issues, _ := lib.Resolve(ctx, wrong); len(issues) != 1 {
		t.Fatalf("source used as destination: %+v", issues)
	}
	if err := lib.Delete(ctx, gw.ID); err != nil {
		t.Fatal(err)
	}
	if _, issues, _ := lib.Resolve(ctx, spec); len(issues) != 1 || !strings.Contains(issues[0].Message, "no longer exists") {
		t.Fatalf("deleted item: %+v", issues)
	}
	if err := lib.Delete(ctx, uuid.New()); !errors.Is(err, pipeline.ErrLibraryNotFound) {
		t.Fatalf("delete unknown: %v", err)
	}
	if items, _ := lib.List(ctx); len(items) != 1 || items[0].Name != "in" {
		t.Fatalf("list = %+v", items)
	}
}
