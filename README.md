# auto-mon-collector

**An installer for the official OpenTelemetry Collector (`otelcol-contrib`) that looks at a Linux host and sets
up monitoring for what it finds.** It is not a collector distribution of its own.

> **Status: early development.** Nothing is usable yet. The design is in [docs/design.md](docs/design.md).

## What it will do

```bash
curl -fsSL https://github.com/NABIXcorp/auto-mon-collector/releases/latest/download/get.sh | sudo bash
```

1. **Detect**: listening ports, processes, systemd units and known log files (Oracle, Tomcat, Redis, Caddy,
   then PostgreSQL, MySQL, nginx, Docker).
2. **Propose**: what it found and what it would monitor. You confirm.
3. **Ask**: only what it cannot find out: backend endpoint, credentials (typed hidden).
4. **Generate + validate**: the collector configuration, checked with the real collector binary and a short
   test run.
5. **Apply**: only after you say yes. Backup first, rollback on failure.

Data goes over OTLP to any backend (OpenObserve first).

## Principles

- Every run starts as a read-only plan. Nothing changes without an explicit yes.
- Secrets are never shown, logged, passed on the command line or put in a URL.
- The collector runs as its own user with read access to single files only.
- Every value has a sensible default: a normal install is Enter, Enter, password.
- The same answers file installs the same configuration without questions (`--answers … --yes`).

## Building

```bash
go test ./...
CGO_ENABLED=0 go build -o amc ./cmd/amc
./amc version
```

## License

[Apache-2.0](LICENSE). Security issues: see [SECURITY.md](SECURITY.md).
