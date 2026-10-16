# Codestra service API contract: OpenTelemetry Collector

This repository owns the **telemetry-ingress-normalization-redaction-routing-authority** for the Codestra observability, analytics, telemetry, and secrets suite.

## Communication rule

OpenTelemetry Collector keeps its native API and protocol. The shared Codestra control plane in `ingtrader21-spec/Codestra-Telemetry` performs only sanitized health, readiness, contract, topology, and immutable-release read-back. It never proxies native query bodies, ingestion, alert delivery, dashboard mutations, secret values, or credential issuance.

- Canonical hostname: `otel.codestra.media`
- Native exposure: `internal_private`
- Deployment class: `agent`
- Contract: `codestra/api/service-contract.v1.json`

## Native operations

| Method | Path | Category | Access | Control-plane rule |
|---|---|---|---|---|
| `GET` | `/` | health | read_only | never proxied by the Codestra control API |
| `GET` | `/` | readiness | read_only | never proxied by the Codestra control API |
| `GET` | `/metrics` | metrics | read_only | never proxied by the Codestra control API |
| `POST` | `/v1/traces` | ingest | ingest | never proxied by the Codestra control API |
| `POST` | `/v1/metrics` | ingest | ingest | never proxied by the Codestra control API |
| `POST` | `/v1/logs` | ingest | ingest | never proxied by the Codestra control API |

## Suite integrations

| Peer | Direction | Signal | Protocol | Purpose |
|---|---|---|---|---|
| `prometheus` | outbound | `metrics` | `prometheus-scrape` | expose sanitized application metrics |
| `loki` | outbound | `logs` | `otlp-http` | export sanitized application logs |
| `tempo` | outbound | `traces` | `otlp-grpc` | export redacted sampled traces |
| `alloy` | inbound | `metrics-logs-traces` | `otlp` | receive host and service telemetry when Alloy delegates processing |

## Identity and correlation

Every private request should propagate `X-Correlation-ID` and W3C `traceparent` when the native protocol supports them. `request_id`, `trace_id`, and `tenant_id` remain structured, protected, non-indexed fields. Metrics use only the bounded dimensions `codestra_business`, `application`, `service`, `environment`, `server`, `region`, and `deployment`.

Business identity is deployment-controlled. Caller-supplied business identity, cross-business defaults, anonymous management access, insecure TLS verification, and inline credentials are prohibited.

## Release and runtime boundary

The control plane reads source revision and image digest only from deployment environment variables. A valid release requires a 40-character Git SHA and `sha256:<64 lowercase hex>` image digest. This source change does not deploy the service, activate ingestion/scrapes/probes/alerts, issue credentials, or enable any business, communications, financial, or trading mutation.
