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

	clients := make([]client.OpAMPClient, 0, *n)
	for i := range *n {
		uid, err := uuid.NewV7()
		if err != nil {
			log.Fatal(err)
		}
		c := client.NewWebSocket(nil)
		must(c.SetAgentDescription(&protobufs.AgentDescription{
			IdentifyingAttributes: []*protobufs.KeyValue{
				kv("service.name", "otelcol-sim"),
				kv("service.version", "0.140.0"),
				kv("service.instance.id", uid.String()),
			},
			NonIdentifyingAttributes: []*protobufs.KeyValue{
				kv("host.name", fmt.Sprintf("sim-host-%05d", i)),
				kv("os.type", "linux"),
				kv("region", regions[i%len(regions)]),
				kv("env", envs[i%len(envs)]),
			},
		}))
		caps := protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsEffectiveConfig |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsHealth |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsHeartbeat
		must(c.SetCapabilities(&caps))

		health := &protobufs.ComponentHealth{Healthy: true, Status: "StatusOK", StartTimeUnixNano: uint64(time.Now().UnixNano())}
		if rand.IntN(100) < *unhealthyPct {
			health.Healthy, health.Status, health.LastError = false, "StatusRecoverableError", "exporter/otlp: connection refused"
		}
		must(c.SetHealth(health))

		must(c.Start(context.Background(), types.StartSettings{
			OpAMPServerURL:    *url,
			Header:            header,
			TLSConfig:         tlsCfg,
			InstanceUid:       types.InstanceUid(uid),
			HeartbeatInterval: heartbeat,
			Callbacks: types.Callbacks{
				OnConnectFailed: func(_ context.Context, err error) { log.Printf("agent %s connect failed: %v", uid, err) },
				GetEffectiveConfig: func(context.Context) (*protobufs.EffectiveConfig, error) {
					return &protobufs.EffectiveConfig{ConfigMap: &protobufs.AgentConfigMap{
						ConfigMap: map[string]*protobufs.AgentConfigObject{
							"": {Body: []byte(effectiveConfig), ContentType: "text/yaml"},
						},
					}}, nil
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
