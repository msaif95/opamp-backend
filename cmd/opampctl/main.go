// opampctl is the command-line client for OpAMP Fleet: list collectors,
// apply configs and groups from files (for GitOps), start and control bulk
// pushes, and restart or stop collectors.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

const usage = `opampctl - command-line client for OpAMP Fleet

Connection (flags or environment):
  --url    console URL, e.g. https://opamp.example.com      (OPAMP_URL)
  --token  API token from the console's Agent credentials   (OPAMP_TOKEN)
  --project  project to act in, by name; omit for resources outside any project   (OPAMP_PROJECT)

Commands:
  agents [--selector k=v,k=v] [--limit N] [-o json]    list collectors
  configs [-o json]                                    list configs
  config <name>[@version]                              print a config's collector YAML
  groups [-o json]                                     list groups
  apply -f <file|dir> [--dry-run]                      create or update configs and groups from YAML files
  push --config <name>[@version] (--group <name> | --selector k=v,k=v | --all)
       [--batch-size N] [--max-failure-pct P] [--auto-rollback] [--approve-each-batch] [--wait]
                                                       start a bulk push
  rollouts [-o json]                                   list bulk pushes
  rollout <id> [pause|resume|abort|rollback]           show or control a bulk push
  restart|stop|resume <collector-uid>                  restart a collector, or stop/resume its collection
  version

apply never deletes anything and never pushes to collectors; use push for that.
Exit status: 0 on success, 1 on error, 2 when "push --wait" ends in anything but completed.
`

var version = "dev"

func main() {
	code, err := run(os.Args[1:], os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func run(args []string, out io.Writer) (int, error) {
	global := flag.NewFlagSet("opampctl", flag.ContinueOnError)
	global.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	url := global.String("url", os.Getenv("OPAMP_URL"), "")
	token := global.String("token", os.Getenv("OPAMP_TOKEN"), "")
	project := global.String("project", os.Getenv("OPAMP_PROJECT"), "")
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 1, err
	}
	rest := global.Args()
	if len(rest) == 0 || rest[0] == "help" {
		fmt.Fprint(out, usage)
		return 0, nil
	}
	cmd, rest := rest[0], rest[1:]
	if cmd == "version" {
		fmt.Fprintln(out, "opampctl", version)
		return 0, nil
	}
	if *url == "" || *token == "" {
		return 1, errors.New("set the console URL and an API token: --url/--token or OPAMP_URL/OPAMP_TOKEN")
	}
	c := newClient(*url, *token)
	if *project != "" {
		if err := c.useProject(*project); err != nil {
			return 1, err
		}
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	output := fs.String("o", "table", "output format: table or json")
	table := func(header string, rows func(w io.Writer)) {
		w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, header)
		rows(w)
		w.Flush()
	}
	asJSON := func(v any) (int, error) {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return 0, enc.Encode(v)
	}

	switch cmd {
	case "agents":
		selector := fs.String("selector", "", "k=v,k=v")
		limit := fs.Int("limit", 100, "")
		if err := fs.Parse(rest); err != nil {
			return 1, err
		}
		sel, err := parseSelector(*selector)
		if err != nil {
			return 1, err
		}
		one := map[string]string{}
		for k, v := range sel {
			if len(v) != 1 {
				return 1, fmt.Errorf("agents --selector takes one value per key (got %d for %s)", len(v), k)
			}
			one[k] = v[0]
		}
		agents, total, err := c.agents(one, *limit)
		if err != nil {
			return 1, err
		}
		if *output == "json" {
			return asJSON(agents)
		}
		table("HOST\tSTATUS\tVERSION\tCONFIG\tUID", func(w io.Writer) {
			for _, a := range agents {
				status := "offline"
				switch {
				case a.Connected && a.Paused:
					status = "paused"
				case a.Connected && a.Healthy != nil && !*a.Healthy:
					status = "unhealthy"
				case a.Connected:
					status = "healthy"
				}
				cfg := "-"
				if a.Config != nil {
					cfg = fmt.Sprintf("%s v%d", a.Config.Name, a.Config.Version)
					if !a.Config.InSync {
						cfg += " (not in sync)"
					}
				}
				ver := "-"
				if a.Version != nil {
					ver = *a.Version
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", a.Attributes["host.name"], status, ver, cfg, a.UID)
			}
		})
		if total > len(agents) {
			fmt.Fprintf(out, "showing %d of %d; raise --limit to see more\n", len(agents), total)
		}
		return 0, nil

	case "configs":
		if err := fs.Parse(rest); err != nil {
			return 1, err
		}
		configs, err := c.configs()
		if err != nil {
			return 1, err
		}
		if *output == "json" {
			return asJSON(configs)
		}
		table("NAME\tLATEST\tASSIGNED AGENTS\tORIGIN", func(w io.Writer) {
			for _, cfg := range configs {
				fmt.Fprintf(w, "%s\tv%d\t%d\t%s\n", cfg.Name, cfg.LatestVersion, cfg.Assigned, cfg.Origin)
			}
		})
		return 0, nil

	case "config":
		if len(rest) != 1 {
			return 1, errors.New("usage: opampctl config <name>[@version]")
		}
		v, err := resolveVersion(c, rest[0])
		if err != nil {
			return 1, err
		}
		fmt.Fprint(out, v.Body)
		return 0, nil

	case "groups":
		if err := fs.Parse(rest); err != nil {
			return 1, err
		}
		groups, err := c.groups()
		if err != nil {
			return 1, err
		}
		if *output == "json" {
			return asJSON(groups)
		}
		table("NAME\tAGENTS\tSELECTOR", func(w io.Writer) {
			for _, g := range groups {
				fmt.Fprintf(w, "%s\t%d\t%s\n", g.Name, g.Members, formatSelector(g.Selector))
			}
		})
		return 0, nil

	case "apply":
		file := fs.String("f", "", "file or directory")
		dryRun := fs.Bool("dry-run", false, "")
		if err := fs.Parse(rest); err != nil {
			return 1, err
		}
		if *file == "" {
			return 1, errors.New("usage: opampctl apply -f <file|dir> [--dry-run]")
		}
		resources, err := loadResources(*file)
		if err != nil {
			return 1, err
		}
		changed, err := apply(c, resources, *dryRun, out)
		if err != nil {
			return 1, err
		}
		fmt.Fprintf(out, "%d resources, %d changed\n", len(resources), changed)
		return 0, nil

	case "push":
		config := fs.String("config", "", "name[@version]")
		groupName := fs.String("group", "", "")
		selector := fs.String("selector", "", "k=v,k=v")
		all := fs.Bool("all", false, "target every collector")
		batch := fs.Int("batch-size", 100, "")
		maxFail := fs.Float64("max-failure-pct", 2, "")
		autoRollback := fs.Bool("auto-rollback", false, "")
		approve := fs.Bool("approve-each-batch", false, "")
		wait := fs.Bool("wait", false, "wait until the push finishes or pauses")
		if err := fs.Parse(rest); err != nil {
			return 1, err
		}
		targets := 0
		for _, set := range []bool{*groupName != "", *selector != "", *all} {
			if set {
				targets++
			}
		}
		if *config == "" || targets != 1 {
			return 1, errors.New("usage: opampctl push --config <name>[@version] and exactly one of --group, --selector or --all")
		}
		v, err := resolveVersion(c, *config)
		if err != nil {
			return 1, err
		}
		req := map[string]any{
			"config_version_id": v.ID, "batch_size": *batch, "max_failure_pct": *maxFail,
			"auto_rollback": *autoRollback, "manual_approval": *approve, "all_agents": *all, "selector": map[string][]string{},
		}
		switch {
		case *groupName != "":
			groups, err := c.groups()
			if err != nil {
				return 1, err
			}
			found := false
			for _, g := range groups {
				if g.Name == *groupName && c.inProject(g.ProjectID) {
					req["group_id"], req["selector"], found = g.ID, g.Selector, true
				}
			}
			if !found {
				return 1, fmt.Errorf("no group named %q", *groupName)
			}
		case *selector != "":
			sel, err := parseSelector(*selector)
			if err != nil {
				return 1, err
			}
			req["selector"] = sel
		}
		var ro rolloutInfo
		if err := c.do("POST", "/rollouts", c.projectField(req), &ro); err != nil {
			return 1, err
		}
		fmt.Fprintf(out, "started push %s: %s v%d to %d agents in %d batches\n", ro.ID, ro.ConfigName, ro.ConfigVersion, ro.TotalAgents, ro.TotalBatches)
		if !*wait {
			return 0, nil
		}
		for {
			time.Sleep(3 * time.Second)
			cur, err := c.rollout(ro.ID)
			if err != nil {
				return 1, err
			}
			if cur.Status == "running" {
				continue
			}
			printRollout(out, cur)
			if cur.Status != "completed" {
				return 2, nil
			}
			return 0, nil
		}

	case "rollouts":
		if err := fs.Parse(rest); err != nil {
			return 1, err
		}
		var list struct {
			Rollouts []rolloutInfo `json:"rollouts"`
		}
		if err := c.do("GET", "/rollouts", nil, &list); err != nil {
			return 1, err
		}
		if *output == "json" {
			return asJSON(list.Rollouts)
		}
		table("ID\tCONFIG\tSTATUS\tAGENTS\tBATCHES\tBY", func(w io.Writer) {
			for _, r := range list.Rollouts {
				fmt.Fprintf(w, "%s\t%s v%d\t%s\t%d\t%d/%d\t%s\n", r.ID, r.ConfigName, r.ConfigVersion, r.Status, r.TotalAgents, r.BatchesReleased, r.TotalBatches, r.CreatedBy)
			}
		})
		return 0, nil

	case "rollout":
		if len(rest) < 1 || len(rest) > 2 {
			return 1, errors.New("usage: opampctl rollout <id> [pause|resume|abort|rollback]")
		}
		if len(rest) == 2 {
			switch rest[1] {
			case "pause", "resume", "abort", "rollback":
			default:
				return 1, fmt.Errorf("unknown action %q (pause, resume, abort or rollback)", rest[1])
			}
			if err := c.do("POST", "/rollouts/"+rest[0]+"/"+rest[1], nil, nil); err != nil {
				return 1, err
			}
		}
		cur, err := c.rollout(rest[0])
		if err != nil {
			return 1, err
		}
		printRollout(out, cur)
		return 0, nil

	case "restart", "stop", "resume":
		if len(rest) != 1 {
			return 1, fmt.Errorf("usage: opampctl %s <collector-uid>", cmd)
		}
		path := map[string]string{"restart": "restart", "stop": "pause", "resume": "resume"}[cmd]
		if err := c.do("POST", "/agents/"+rest[0]+"/"+path, nil, nil); err != nil {
			return 1, err
		}
		fmt.Fprintln(out, map[string]string{"restart": "restart requested", "stop": "collection stopped", "resume": "collection resumed"}[cmd])
		return 0, nil
	}
	return 1, fmt.Errorf("unknown command %q; run opampctl help", cmd)
}

func printRollout(out io.Writer, r *rolloutInfo) {
	keys := make([]string, 0, len(r.Counts))
	for k := range r.Counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var counts []string
	for _, k := range keys {
		counts = append(counts, fmt.Sprintf("%s %d", k, r.Counts[k]))
	}
	fmt.Fprintf(out, "push %s: %s v%d, %s, batch %d of %d, %d agents (%s)\n",
		r.ID, r.ConfigName, r.ConfigVersion, r.Status, r.BatchesReleased, r.TotalBatches, r.TotalAgents, strings.Join(counts, ", "))
	if r.Error != nil && *r.Error != "" {
		fmt.Fprintln(out, " ", *r.Error)
	}
}

// resolveVersion turns "name" or "name@3" into a config version (the latest when no number is given).
func resolveVersion(c *client, ref string) (*configVersion, error) {
	name, num, pinned := strings.Cut(ref, "@")
	cfg, err := c.configByName(name)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("no config named %q", name)
	}
	n := cfg.LatestVersion
	if pinned {
		if n, err = strconv.Atoi(strings.TrimPrefix(num, "v")); err != nil {
			return nil, fmt.Errorf("bad version in %q", ref)
		}
	}
	return c.version(cfg.ID, n)
}

// parseSelector reads "env=prod,region=us-east-1,region=eu-west-1" into attribute → values.
func parseSelector(s string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("bad selector %q: expected key=value", part)
		}
		out[k] = append(out[k], v)
	}
	return out, nil
}

func formatSelector(sel map[string][]string) string {
	keys := make([]string, 0, len(sel))
	for k := range sel {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+strings.Join(sel[k], "|"))
	}
	return strings.Join(parts, " ")
}
