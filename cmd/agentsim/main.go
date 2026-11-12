// Command agentsim runs N simulated OpAMP agents against a backend. It is
// used for local development and as the basis for scale validation.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/open-telemetry/opamp-go/client"
	"github.com/open-telemetry/opamp-go/client/types"
	"github.com/open-telemetry/opamp-go/protobufs"
)

const effectiveConfig = `receivers:
  otlp:
    protocols:
      grpc:
exporters:
  debug:
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [debug]
`

func main() {
	url := flag.String("url", "ws://localhost:4320/v1/opamp", "OpAMP server URL")
	token := flag.String("token", os.Getenv("OPAMP_API_KEY"), "agent API key (or set OPAMP_API_KEY)")
	n := flag.Int("n", 1, "number of simulated agents")
	heartbeat := flag.Duration("heartbeat", 30*time.Second, "heartbeat interval")
	unhealthyPct := flag.Int("unhealthy-pct", 0, "percentage of agents reporting unhealthy")
	applyFailPct := flag.Int("apply-fail-pct", 0, "percentage of agents that fail to apply remote config")
	caFile := flag.String("ca", "", "CA bundle to verify the server (wss only)")
	certFile := flag.String("cert", "", "client certificate for mTLS")
	keyFile := flag.String("key", "", "client key for mTLS")
	flag.Parse()

	var tlsCfg *tls.Config
	if *caFile != "" || *certFile != "" {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
		if *caFile != "" {
			pem, err := os.ReadFile(*caFile)
			must(err)
			tlsCfg.RootCAs = x509.NewCertPool()
			if !tlsCfg.RootCAs.AppendCertsFromPEM(pem) {
				log.Fatalf("no certificates in %s", *caFile)
			}
		}
		if *certFile != "" {
			cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
			must(err)
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
	}
	header := http.Header{}
	if *token != "" {
		header.Set("Authorization", "Bearer "+*token)
	}

	regions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-south-1"}
	envs := []string{"prod", "staging", "dev"}
	teams := []string{"sre", "platform", "payments", "search", "data"}
	// region -> cloud provider and datacenters
	clouds := map[string]string{"us-east-1": "aws", "us-west-2": "aws", "eu-west-1": "azure", "ap-south-1": "gcp"}
	dcs := map[string][]string{
		"us-east-1": {"iad1", "iad2"}, "us-west-2": {"pdx1"}, "eu-west-1": {"dub1", "dub2"}, "ap-south-1": {"bom1"},
	}

	clients := make([]client.OpAMPClient, 0, *n)
	for i := range *n {
		uid, err := uuid.NewV7()
		if err != nil {
			log.Fatal(err)
		}
		c := client.NewWebSocket(nil)
		region := regions[i%len(regions)]
		must(c.SetAgentDescription(&protobufs.AgentDescription{
			IdentifyingAttributes: []*protobufs.KeyValue{
				kv("service.name", "otelcol-sim"),
				kv("service.version", "0.140.0"),
				kv("service.instance.id", uid.String()),
			},
			NonIdentifyingAttributes: []*protobufs.KeyValue{
				kv("host.name", fmt.Sprintf("sim-host-%05d", i)),
				kv("os.type", "linux"),
				kv("region", region),
				kv("cloud.provider", clouds[region]),
				kv("dc", dcs[region][i%len(dcs[region])]),
				kv("env", envs[i%len(envs)]),
				kv("team", teams[i%len(teams)]),
			},
		}))
		caps := protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsEffectiveConfig |
			protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsRemoteConfig |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsHealth |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsHeartbeat
		must(c.SetCapabilities(&caps))

		health := &protobufs.ComponentHealth{Healthy: true, Status: "StatusOK", StartTimeUnixNano: uint64(time.Now().UnixNano())}
		if rand.IntN(100) < *unhealthyPct {
			health.Healthy, health.Status, health.LastError = false, "StatusRecoverableError", "exporter/otlp: connection refused"
		}
		must(c.SetHealth(health))

		var (
			mu        sync.Mutex
			effective = []byte(effectiveConfig)
		)
		failsApply := rand.IntN(100) < *applyFailPct

		must(c.Start(context.Background(), types.StartSettings{
			OpAMPServerURL:    *url,
			Header:            header,
			TLSConfig:         tlsCfg,
			InstanceUid:       types.InstanceUid(uid),
			HeartbeatInterval: heartbeat,
			Callbacks: types.Callbacks{
				OnConnectFailed: func(_ context.Context, err error) { log.Printf("agent %s connect failed: %v", uid, err) },
				GetEffectiveConfig: func(context.Context) (*protobufs.EffectiveConfig, error) {
					mu.Lock()
					defer mu.Unlock()
					return &protobufs.EffectiveConfig{ConfigMap: &protobufs.AgentConfigMap{
						ConfigMap: map[string]*protobufs.AgentConfigObject{
							"": {Body: effective, ContentType: "text/yaml"},
						},
					}}, nil
				},
				// Mimics the Supervisor: report APPLYING, "restart" the
				// collector, then report APPLIED with the new effective
				// config, or FAILED and keep the old one.
				OnMessage: func(_ context.Context, msg *types.MessageData) {
					rc := msg.RemoteConfig
					if rc == nil {
						return
					}
					status := func(s protobufs.RemoteConfigStatuses, errMsg string) {
						_ = c.SetRemoteConfigStatus(&protobufs.RemoteConfigStatus{
							LastRemoteConfigHash: rc.ConfigHash, Status: s, ErrorMessage: errMsg})
					}
					status(protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLYING, "")
					go func() {
						time.Sleep(time.Duration(500+rand.IntN(1500)) * time.Millisecond)
						if failsApply {
							status(protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED,
								"collector failed to start with new config: simulated failure")
							return
						}
						mu.Lock()
						effective = rc.Config.ConfigMap[""].Body
						mu.Unlock()
						status(protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED, "")
						_ = c.UpdateEffectiveConfig(context.Background())
					}()
				},
			},
		}))
		clients = append(clients, c)
	}
	log.Printf("started %d simulated agents against %s", *n, *url)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	for _, c := range clients {
		_ = c.Stop(context.Background())
	}
}

func kv(k, v string) *protobufs.KeyValue {
	return &protobufs.KeyValue{Key: k, Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: v}}}
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
