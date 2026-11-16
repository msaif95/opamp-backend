// Package opampctldoc holds the opampctl usage text, shared by the tool
// itself and by the console's documentation page so the two cannot drift.
package opampctldoc

// Usage is what `opampctl help` prints.
const Usage = `opampctl - command-line client for OpAMP Fleet

Connection (flags or environment):
  --url    console URL, e.g. https://opamp.example.com      (OPAMP_URL)
  --token  API token from the console's Agent credentials   (OPAMP_TOKEN)
  --project  project to act in, by name; needed to create or push anything       (OPAMP_PROJECT)

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
