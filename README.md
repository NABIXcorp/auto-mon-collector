# auto-mon-collector

**An installer for the official OpenTelemetry Collector (`otelcol-contrib`) that looks at a Linux host and sets
up monitoring for what it finds.** It is not a collector distribution of its own.

> **Status: v0.6.0, early.** Detection, generator, interactive questions and the install engine are tested on
> real hosts. Releases are signed; the one-liner below works. Design: [docs/design.md](docs/design.md).
> v0.2.0: optional `project:` in answers.yaml (resource attribute `project` on all data), host uptime.
> v0.3.0: Tomcat started by systemd (daily `catalina.*.log` / `localhost.*.log`), renamed access logs, the log
> paths can be answered (`services.tomcat.access_log` / `logs`); the project is asked interactively.
> v0.4.0: Oracle CDB root checks with a common `C##` user (`services.oracle.cdb_service`): PDB open state,
> database role + open mode, process / session limits, fast recovery area usage.
> v0.5.0: kernel warnings / errors (OOM killer, hung tasks, disk errors) via a small journal helper unit
> (`monitoring-kmsg`, the only unit with journal access) -> stream `kernel`.
> v0.6.0: top processes by CPU and memory every minute (`monitoring-procs`, command names only) -> stream `processes`.

## What it does

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

## Verify instead of trusting

`get.sh` checks an ECDSA P-256 signature over `SHA256SUMS` (public key: [keys/amc-release.pub](keys/amc-release.pub),
also embedded in `get.sh`) and the binary's sha256 before it runs anything; without `openssl` it stops. To read it first:

```bash
curl -fsSLO https://github.com/NABIXcorp/auto-mon-collector/releases/latest/download/get.sh
less get.sh && sudo bash get.sh            # AMC_VERSION=v0.2.0 pins a release
```

## Principles

- Every run starts as a read-only plan. Nothing changes without an explicit yes.
- Secrets are never shown, logged, passed on the command line or put in a URL.
- The collector runs as its own user with read access to single files only.
- Every value has a sensible default: a normal install is Enter, Enter, password.
- The same answers file installs the same configuration without questions (`--answers … --yes`).

## Try it now (build from source, as root)

```bash
sudo amc detect                       # read-only: what runs on this host
sudo amc                              # asks what a scan cannot know, then a full plan; "Apply now?" at the end
sudo amc plan --answers answers.yaml  # the same without questions (automation), see examples/app-host
sudo amc uninstall                    # check mode; --yes removes (secrets / data / user kept unless --purge*)
```

Secrets (backend auth header, database password) are typed hidden or come from
`/opt/monitoring/secrets/collector.env` (root 600); they are never shown, logged or stored in `answers.yaml`.

## Building

```bash
go test ./...
CGO_ENABLED=0 go build -o amc ./cmd/amc
./amc version
```

## License

[Apache-2.0](LICENSE). Security issues: see [SECURITY.md](SECURITY.md).
