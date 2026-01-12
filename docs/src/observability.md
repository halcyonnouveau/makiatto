# Observability

This guide sets up a Grafana dashboard for a Makiatto cluster using open-source components.

## Architecture

```
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  Makiatto   │ │  Makiatto   │ │  Makiatto   │
│   Node A    │ │   Node B    │ │   Node C    │
└──────┬──────┘ └──────┬──────┘ └──────┬──────┘
       │               │               │
       └───────────────┼───────────────┘
                       ▼
           ┌────────────────────────┐
           │       Collector        │
           │     (spanmetrics)      │
           └─────┬───────────┬──────┘
                 │           │
                 ▼           ▼
           ┌─────────┐ ┌────────────┐
           │  Tempo  │ │ Prometheus │
           └────┬────┘ └──────┬─────┘
                │             │
                └──────┬──────┘
                       ▼
                  ┌─────────┐
                  │ Grafana │
                  └─────────┘
```

Makiatto nodes send traces directly to a central collector. The collector generates RED metrics (rate, errors, duration) via the spanmetrics connector, forwards traces to Tempo, and exposes metrics for Prometheus.

## Prerequisites

Install the following on the observability server:

```bash
# Debian/Ubuntu
apt install podman wireguard

# Fedora/RHEL
dnf install podman wireguard-tools
```

## 1. Connect to the WireGuard mesh

Makiatto nodes communicate over a private WireGuard network. Add the observability server as an external peer so nodes can send traces securely without exposing the collector publicly.

### Generate a WireGuard keypair

On the observability server:

```bash
wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key
chmod 600 /etc/wireguard/private.key
```

### Register the peer

Copy the public key from the observability server, then from your workstation:

```bash
maki peer add o11y \
  --wg-pubkey "PUBLIC_KEY_HERE" \
  --endpoint your-server-ip
```

```admonish info
Name the peer with "o11y" (at the start or end) so Makiatto auto-discovers it as the telemetry endpoint. Examples: `o11y`, `o11y-grafana`, `metrics-o11y`.
```

This assigns a WireGuard address automatically. To see the full configuration:

```bash
maki peer wg-config o11y
```

```admonish note
Note the `Address` line (e.g. `10.44.44.5/32`) - you'll need this for the collector config.
```

### Configure WireGuard

Save the output as `/etc/wireguard/wg0.conf` on the observability server, replacing `<private-key>` with the contents of `/etc/wireguard/private.key`.

Start the interface:

```bash
wg-quick up wg0
systemctl enable wg-quick@wg0
```

Verify connectivity by pinging a Makiatto node's WireGuard address (e.g. `ping 10.44.44.1`).

## 2. Deploy the observability stack

We'll use Podman Quadlets for systemd-managed containers.

### Config files

```bash
mkdir -p /etc/makiatto-o11y
```

Create `/etc/makiatto-o11y/tempo.yaml`:

```yaml
stream_over_http_enabled: true

server:
  http_listen_port: 3200
  grpc_listen_port: 9095

distributor:
  receivers:
    otlp:
      protocols:
        grpc:
          endpoint: 0.0.0.0:4317

storage:
  trace:
    backend: local
    local:
      path: /var/tempo/traces
    wal:
      path: /var/tempo/wal
```

Create `/etc/makiatto-o11y/otelcol.yaml`:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

connectors:
  spanmetrics:
    namespace: traces.spanmetrics
    dimensions:
      - name: cdn.cache.hit

exporters:
  otlp/tempo:
    endpoint: systemd-tempo:4317
    tls:
      insecure: true
  prometheus:
    endpoint: 0.0.0.0:9464

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [spanmetrics, otlp/tempo]
    metrics:
      receivers: [spanmetrics]
      exporters: [prometheus]
```

Create `/etc/makiatto-o11y/prometheus.yml`:

```yaml
scrape_configs:
  - job_name: makiatto-spanmetrics
    static_configs:
      - targets:
          - systemd-otelcol:9464
```

### Quadlet units

Create these files in `/etc/containers/systemd/`.

**o11y.network:**

```ini
[Network]
```

**tempo.container:**

```ini
[Container]
Image=docker.io/grafana/tempo:latest
Exec=-config.file=/etc/tempo/config.yaml
Volume=/etc/makiatto-o11y/tempo.yaml:/etc/tempo/config.yaml:ro
Volume=tempo-data:/var/tempo
Network=o11y.network

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

**tempo-data.volume:**

```ini
[Volume]
```

**otelcol.container** (replace `10.44.44.X` with your WireGuard address):

```ini
[Container]
Image=docker.io/otel/opentelemetry-collector-contrib:latest
PublishPort=10.44.44.X:4317:4317
Volume=/etc/makiatto-o11y/otelcol.yaml:/etc/otelcol-contrib/config.yaml:ro
Network=o11y.network

[Unit]
Requires=tempo.service
After=tempo.service

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

**prometheus.container:**

```ini
[Container]
Image=docker.io/prom/prometheus:latest
Volume=/etc/makiatto-o11y/prometheus.yml:/etc/prometheus/prometheus.yml:ro
Network=o11y.network

[Unit]
Requires=otelcol.service
After=otelcol.service

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

**grafana.container:**

```ini
[Container]
Image=docker.io/grafana/grafana:latest
PublishPort=3000:3000
Volume=grafana-data:/var/lib/grafana
Network=o11y.network

[Unit]
Requires=prometheus.service tempo.service
After=prometheus.service tempo.service

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

**grafana-data.volume:**

```ini
[Volume]
```

### Start the stack

```bash
systemctl daemon-reload
systemctl start grafana
```

The dependencies will start Tempo, otelcol, and Prometheus automatically. Services restart on boot.

### Optional: HTTPS with Caddy

To access Grafana over HTTPS, add Caddy as a reverse proxy.

Remove `PublishPort=3000:3000` from `grafana.container`, then create:

**Caddyfile** at `/etc/makiatto-o11y/Caddyfile`:

```
grafana.example.com {
	reverse_proxy systemd-grafana:3000
}
```

**caddy.container:**

```ini
[Container]
Image=docker.io/library/caddy:latest
PublishPort=443:443
PublishPort=80:80
Volume=/etc/makiatto-o11y/Caddyfile:/etc/caddy/Caddyfile:ro
Volume=caddy-data:/data
Network=o11y.network

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

**caddy-data.volume:**

```ini
[Volume]
```

Reload and start Caddy:

```bash
systemctl daemon-reload
systemctl start caddy
```

Caddy automatically obtains a TLS certificate from Let's Encrypt.

## 3. Restart Makiatto nodes

Restart Makiatto on all nodes:

```bash
maki machine restart
```

Makiatto automatically discovers the OTLP endpoint by finding the external peer named with "o11y" and sets the service name to `makiatto.{node_name}`.

To override auto-discovery or tune settings:

```toml
[o11y]
otlp_endpoint = "http://10.44.44.5:4317"  # Optional: override auto-discovery
sampling_ratio = 0.1       # Sample 10% of traces (default), errors/slow always captured
tracing_enabled = true     # Set to false to disable trace export
metrics_enabled = true     # Set to false to disable metrics export
logging_enabled = true     # Set to false to disable log export
```

```admonish note
If `otlp_endpoint` is not set, Makiatto auto-discovers it from external peers. If no o11y peer is found, telemetry export is disabled (console logging still works).
```

## 4. Configure Grafana

1. Sign in at `http://<server-ip>:3000` (or your Caddy domain if configured) with `admin`/`admin`
2. Add data sources:
   - **Prometheus**: `http://systemd-prometheus:9090`
   - **Tempo**: `http://systemd-tempo:3200`

## 5. Build the dashboard

Create panels with these queries:

| Panel | Query |
|-------|-------|
| HTTP request rate | `sum by (service_name) (rate(traces_spanmetrics_calls_total{span_name="http.server"}[5m]))` |
| Error rate | `sum(rate(traces_spanmetrics_errors_total{span_name="http.server"}[5m]))` |
| p95 latency | `histogram_quantile(0.95, sum(rate(traces_spanmetrics_duration_milliseconds_bucket{span_name="http.server"}[5m])) by (le))` |
| Cache hit ratio | `sum(rate(traces_spanmetrics_calls_total{span_name="cdn.file.read", cdn_cache_hit="true"}[5m])) / sum(rate(traces_spanmetrics_calls_total{span_name="cdn.file.read"}[5m]))` |
| WASM p95 execution | `histogram_quantile(0.95, sum(rate(traces_spanmetrics_duration_milliseconds_bucket{span_name="wasm.invoke"}[5m])) by (le))` |

Add a Tempo trace panel filtered by `service.name =~ "makiatto.*"` and enable exemplar linking on the Prometheus panels to jump from metric spikes to traces.

## 6. Optional alerting

Add these rules in Prometheus:

- `http.server` error rate > 1% for 5 minutes
- `http.server` p95 latency > 250ms for 10 minutes
- Cache hit ratio < 80% for 15 minutes

Enable the Prometheus Alertmanager integration in Grafana to surface these alerts.
