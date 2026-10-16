# Kyyow integration

This repository is the source authority for **opentelemetry** in the Kyyow platform. Its Kyyow boundary is machine-readable in [kyyow-integration.v1.json](kyyow-integration.v1.json).

The component is **private** and its native ports are not made public by this contract. Keycloak owns identity, OpenBao owns secret delivery, and Middleware remains the sole writer to Odoo. Grafana and Superset consume read-only data paths.

This contract is source-complete but deliberately does not claim a live deployment. Production activation requires an immutable image/configuration digest, private-network verification, restore and rollback evidence, and a separately approved cutover.

## Source topology and limits

`codestra/collector.yaml` exports directly to Loki and Tempo and serves Prometheus metrics on 8889; Alloy is not an OTLP intermediary. OTLP uses 4317/4318, collector self-metrics 8888, and health 13133. `transform/logs` deletes selected attributes and truncates attributes with `error_mode: ignore`; it does not sanitize arbitrary record bodies. Resource processing removes incoming tenant identifiers and uses configured business/aggregate scope. Kyyow tenant telemetry and body sanitization need separate implementation and evidence before activation.

All listed ports are private or loopback. This correction does not authorize runtime activation.
