package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// resource is one document in an apply file.
//
//	kind: Config
//	name: linux-hosts
//	description: Host metrics for Linux servers
//	bodyFile: linux-hosts.collector.yaml   # or inline `body: |`
//	---
//	kind: Group
//	name: prod-sre
//	selector:
//	  env: [prod]
//	  team: [sre]
type resource struct {
	Kind        string              `yaml:"kind"`
	Name        string              `yaml:"name"`
	Description string              `yaml:"description"`
	Body        string              `yaml:"body"`
	BodyFile    string              `yaml:"bodyFile"`
	Selector    map[string][]string `yaml:"selector"`

	source string // file it came from, for messages
}

// loadResources reads every resource from a file, or from all .yaml/.yml
// files under a directory (in name order, so runs are repeatable).
func loadResources(path string) ([]resource, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var files []string
	if !info.IsDir() {
		files = []string{path}
	} else {
		err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
				files = append(files, p)
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(files)
	}

	var out []resource
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		for doc := 1; ; doc++ {
			var r resource
			err := dec.Decode(&r)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("%s: %w", file, err)
			}
			// A directory may also hold the collector configs that bodyFile points at; skip anything that is not a resource.
			if r.Kind == "" {
				if info.IsDir() {
					continue
				}
				return nil, fmt.Errorf("%s (document %d): missing kind", file, doc)
			}
			r.source = file
			if r.Name == "" {
				return nil, fmt.Errorf("%s (document %d): %s has no name", file, doc, r.Kind)
			}
			switch r.Kind {
			case "Config":
				if (r.Body == "") == (r.BodyFile == "") {
					return nil, fmt.Errorf("%s: config %q needs exactly one of body or bodyFile", file, r.Name)
				}
				if r.BodyFile != "" {
					body, err := os.ReadFile(filepath.Join(filepath.Dir(file), r.BodyFile))
					if err != nil {
						return nil, fmt.Errorf("%s: config %q: %w", file, r.Name, err)
					}
					r.Body = string(body)
				}
			case "Group":
				if len(r.Selector) == 0 {
					return nil, fmt.Errorf("%s: group %q needs a selector", file, r.Name)
				}
			default:
				return nil, fmt.Errorf("%s: unknown kind %q (expected Config or Group)", file, r.Kind)
			}
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no resources found in %s", path)
	}
	return out, nil
}

// apply makes the server match the resources. It only ever creates or
// updates; nothing is deleted and nothing is pushed to collectors. With
// dryRun it reports what would change and validates configs without saving.
func apply(c *client, resources []resource, dryRun bool, out io.Writer) (changed int, err error) {
	prefix := ""
	if dryRun {
		prefix = "(dry run) "
	}
	report := func(r resource, what string) {
		fmt.Fprintf(out, "%s%s %q: %s\n", prefix, strings.ToLower(r.Kind), r.Name, what)
	}
	configs, err := c.configs()
	if err != nil {
		return 0, err
	}
	groups, err := c.groups()
	if err != nil {
		return 0, err
	}

	for _, r := range resources {
		switch r.Kind {
		case "Config":
			var existing *configSummary
			for i := range configs {
				if configs[i].Name == r.Name && c.inProject(configs[i].ProjectID) {
					existing = &configs[i]
				}
			}
			if existing != nil {
				latest, err := c.version(existing.ID, existing.LatestVersion)
				if err != nil {
					return changed, err
				}
				if latest.Body == r.Body {
					report(r, fmt.Sprintf("unchanged (v%d)", latest.Version))
					continue
				}
			}
			// Validate first, also in a real run: one bad config should not leave earlier ones half applied silently.
			var validation struct {
				Issues []issue `json:"issues"`
			}
			if err := c.do("POST", "/configs/validate", map[string]string{"body": r.Body}, &validation); err != nil {
				return changed, err
			}
			var problems []issue
			for _, i := range validation.Issues {
				if i.Severity == "error" {
					problems = append(problems, i)
				}
			}
			if len(problems) > 0 {
				return changed, fmt.Errorf("config %q (%s) is not valid: %w", r.Name, r.source, &apiError{Status: 422, Message: "validation failed", Issues: problems})
			}
			changed++
			switch {
			case existing == nil && dryRun:
				report(r, "would be created")
			case existing == nil:
				if err := c.do("POST", "/configs", c.projectField(map[string]any{"name": r.Name, "description": r.Description, "body": r.Body}), nil); err != nil {
					return changed, fmt.Errorf("config %q: %w", r.Name, err)
				}
				report(r, "created (v1)")
			case dryRun:
				report(r, fmt.Sprintf("would get a new version (v%d)", existing.LatestVersion+1))
			default:
				var v configVersion
				err := c.do("POST", "/configs/"+existing.ID+"/versions", map[string]string{"body": r.Body, "description": r.Description}, &v)
				if err != nil {
					return changed, fmt.Errorf("config %q: %w", r.Name, err)
				}
				report(r, fmt.Sprintf("new version v%d", v.Version))
			}

		case "Group":
			var existing *group
			for i := range groups {
				if groups[i].Name == r.Name && c.inProject(groups[i].ProjectID) {
					existing = &groups[i]
				}
			}
			body := c.projectField(map[string]any{"name": r.Name, "description": r.Description, "selector": r.Selector})
			switch {
			case existing != nil && existing.Description == r.Description && sameSelector(existing.Selector, r.Selector):
				report(r, "unchanged")
				continue
			case dryRun && existing == nil:
				report(r, "would be created")
			case dryRun:
				report(r, "would be updated")
			case existing == nil:
				if err := c.do("POST", "/groups", body, nil); err != nil {
					return changed, fmt.Errorf("group %q: %w", r.Name, err)
				}
				report(r, "created")
			default:
				if err := c.do("PUT", "/groups/"+existing.ID, body, nil); err != nil {
					return changed, fmt.Errorf("group %q: %w", r.Name, err)
				}
				report(r, "updated")
			}
			changed++
		}
	}
	return changed, nil
}

// sameSelector compares selectors ignoring the order of values.
func sameSelector(a, b map[string][]string) bool {
	norm := func(m map[string][]string) map[string][]string {
		out := map[string][]string{}
		for k, v := range m {
			s := append([]string(nil), v...)
			sort.Strings(s)
			out[k] = s
		}
		return out
	}
	return reflect.DeepEqual(norm(a), norm(b))
}
