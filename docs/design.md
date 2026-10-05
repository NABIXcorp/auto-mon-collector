# auto-mon-collector: host discovery installer for the OpenTelemetry Collector

Status: **draft v0.2** (2026-10-05: default path `/opt/monitoring`, defaults table, finish in one run). Name, license and repository are decided in section 15.
This document is written to become the first commit of a **public** repository: it contains no data about any
real host, network or company. Examples use generic values (`ORCL`, `/u01/app/oracle`, `backend.example.com`).

---

## 1. Purpose

One command turns a Linux server into a monitored host:

```bash
curl -fsSL https://github.com/<org>/auto-mon-collector/releases/latest/download/get.sh | sudo bash
```

The installer **scans the host**, **proposes** what to monitor, **asks** only for what it cannot detect,
**generates** the collector configuration **locally**, **validates** it with the real collector binary, and
installs it only when asked to (`--apply`). Data goes over OTLP to any backend (first target: OpenObserve).

### Goals
- **Safe by default:** every run starts as a read-only plan; nothing changes without an explicit yes
  (`Apply now?` after a clean plan, or `apply` in automation).
- **Easy to finish:** every value has a default (section 6a); a normal install is Enter, Enter, password.
- **No secrets anywhere visible:** never in a URL, argv, log, repo or bundle; typed hidden or read from a file.
- **No host data in the project:** every host-specific value is detected or asked on the host itself.
- **Least privilege:** the collector runs as its own user, read access through single-file ACLs, no admin groups.
- **Same result every time:** the same answers produce byte-identical files (diff-friendly, idempotent).
- **Works on small and old servers:** one static binary, no runtime dependencies.
- **Automation without questions:** `--answers <file> --yes` gives the same result as the interactive run.

### Non-goals (v1)
- No central management server (no OpAMP until it is stable upstream).
- No creation of database users or grants: the installer prints the SQL, a DBA runs it.
- No Kubernetes / container orchestration (host processes first; Docker containers later).
- No full-screen TUI: plain line-by-line prompts work over any SSH session and in logs.
- No eBPF / zero-code instrumentation (possible later as an optional profile).

---

## 2. Scope v1

| Area | v1 |
|---|---|
| OS | RHEL / Rocky / Alma / Oracle Linux 8-9, CentOS 7 (best effort, EOL), Ubuntu 22.04 / 24.04, Debian 12 |
| CPU | amd64, arm64 |
| Init | systemd |
| Collector | `otelcol-contrib`, version + SHA-256 pinned per release |
| Profiles | host (always), Oracle, Tomcat (+ JMX exporter), Redis, Caddy; then PostgreSQL, MySQL/MariaDB, nginx, Docker |
| Backend | any OTLP/HTTP endpoint with a header-based auth; OpenObserve stream layout as the first preset |
| Extras (later) | dashboard and alert generators per backend (OpenObserve first), Telegram as an alert channel |

---

## 3. Roles

| Role | Does |
|---|---|
| **Operator** (SRE / DevOps) | runs the one-liner, answers prompts, approves `--apply` |
| **DBA** | creates the database monitoring user from the printed SQL (read-only views only) |
| **Backend admin** | provides the OTLP endpoint and an ingest-only credential |
| **Contributor** | adds or improves rules / profiles with test fixtures |

---

## 4. Workflow

```
get.sh ──▶ download installer ──▶ verify signature + sha256 ──▶ amc plan  (default, read-only)
                                                                    │
     detect ─▶ propose ─▶ ask ─▶ generate (to a staging dir) ─▶ validate + smoke run ─▶ show diff
                                                                    │
                                                    amc apply [--start]  (only on request)
                                                                    │
                     install binary ─▶ backup ─▶ write files ─▶ ACLs / SELinux ─▶ systemd ─▶ start ─▶ check
```

### 4.0 Before the first run (by hand, once)
- Database monitoring user + grants (SQL printed by `amc sql oracle`, run by a DBA).
- Backend endpoint + ingest credential.
- Outbound HTTPS to GitHub (download) and to the backend.

### 4.1 Download (`get.sh`, short bash)
1. Whole script inside `main() { …; }; main "$@"`: a partly downloaded script never runs.
2. Detect architecture → pick the release asset.
3. Download the installer + `SHA256SUMS` + `SHA256SUMS.minisig`.
4. Verify the signature with the public key **embedded in get.sh**, then the sha256. Mismatch → abort.
5. `exec` the installer with the passed arguments, stdin from `/dev/tty` when available.

### 4.2 Detect (read-only)
Sources, all read directly (no parsing of `ss` / `netstat` output, which differs between distros):
- **Listening sockets:** `/proc/net/tcp`, `/proc/net/tcp6` (state `0A`) → inode → owning PID via `/proc/<pid>/fd`.
- **Processes:** `/proc/<pid>/comm`, `cmdline`, `exe`, `environ` (root only; read, never printed).
- **systemd units:** `systemctl list-units --type=service` (names only).
- **Files:** known paths from the rule catalog (globs), file existence and readability.
- **OS facts:** `/etc/os-release`, architecture, SELinux mode, package manager.

Each rule match produces a **finding** with a confidence (`high` = port + process match, `medium` = one of
them, `low` = file only) and the values it could derive (e.g. Oracle SID from `ora_pmon_<SID>`).

### 4.3 Propose
```
found  host          Rocky Linux 9.4, amd64, SELinux enforcing
found  oracle        port 1521 (tnslsnr), instance ORCL (ora_pmon_ORCL), alert log /u01/.../alert_ORCL.log   [high]
found  tomcat        port 8080, JMX exporter 9404 (javaagent), logs /opt/tomcat/logs                        [high]
maybe  redis         port 6379 (process: redis-server)                                                      [high]
skip   nginx         not running
Enable [oracle, tomcat, redis]? (enter = yes, or list to change):
```

### 4.4 Ask (only what is missing)
| Value | Source order |
|---|---|
| Backend endpoint | answers file → existing host config → prompt (default from preset) |
| Auth header | secrets file → env `AMC_OO_AUTH` → hidden prompt |
| Oracle service name | answers → derived from SID / listener config → prompt with the guess as default |
| Oracle monitoring user / password | answers (user) → hidden prompt (password) |
| HTTP checks (URLs) | answers → prompt (optional, empty = none) |

### 4.5 Generate (staging, still read-only for the system)
Writes to a staging directory: `host.yaml`, `host.env`, `collector.env` (0600), plus the shipped base config
(`config.yaml`, all profiles inside, switched by `host.env`). Output is sorted and stable.

### 4.6 Validate
1. `otelcol-contrib validate` with the staged files and the real binary (downloaded to the staging dir if the
   host has none yet).
2. **Smoke run** (20-25 s, collector in the foreground, exporters pointed at a local sink): every discovered
   receiver must start; any `failed to load` / `failed to start receiver` fails the plan. Reason: `validate`
   does not build `receiver_creator` templates (section 13).
3. Diff against the installed files.

```
validate VALID · smoke run: 7 receivers started, 0 errors
CHANGE config/host.yaml (+12 -3) · NEW secrets/collector.env
Apply now? [Y/n]        (interactive, clean plan only; otherwise: nothing changed, run `apply`)
```

### 4.7 Apply / start
User and directories, collector binary (pinned sha256), backup of the current files, files written, single-file
read ACLs (`setfacl u:<user>:r <file>` + traverse on parent dirs), SELinux label (`semanage`, fallback `chcon`
with a warning), systemd units, start, 20 s health check (`active` + no `error` lines). Failure → automatic
rollback to the backup.

### 4.8 Update, many hosts, removal
- **Update:** same one-liner. The installer reads the existing host config as answers, detects again, asks only
  about new findings, shows the diff.
- **Many hosts:** `--answers hosts/<name>.yaml --secrets-file /root/amc.secrets --yes` (answers files
  live in the operator's private repository; secrets file put on the host by the operator or a vault agent).
- **Removal:** `amc uninstall` (units, files; secrets only after an explicit confirmation).

---

## 5. Two kinds of discovery

| | Install-time (installer) | Runtime (collector) |
|---|---|---|
| Tool | auto-mon-collector rule catalog | `host_observer` + `receiver_creator` |
| Finds | things that need **paths, names, credentials**: log files, Oracle service, JMX exporter, HTTP checks | **ports** that come and go: a service started later is picked up without re-running the installer |
| Output | switches in `host.env`, static receivers in `host.yaml` | receivers started and stopped automatically |

The base config keeps runtime discovery for port-based services. The installer turns on the switches
(e.g. `ORACLE_MON=on`) and adds what a port alone cannot tell.

---

## 6. Configuration layers on the host

Default path **`/opt/monitoring`** (the layout already used in production before this project; `--prefix`
changes it). File and unit names stay the same, so existing installations need no migration.

```
/opt/monitoring/
  bin/otelcol-contrib            pinned collector
  bin/amc                        installer (auto-mon-collector) (for updates / plan / uninstall)
  config/
    config.yaml                  layer 1: shipped base, same everywhere: runtime discovery + all service
                                 profiles, each switched on/off in host.env (v1: profiles live in the base)
    host.yaml                    layer 2: generated (static receivers: log files, checks; full pipelines)
    site.d/*.yaml                layer 3: optional operator overlay (never touched by the installer)
    host.env                     switches, no secrets
  secrets/collector.env          0600 root, never printed, never in a bundle or repo
  data/                          the only writable dir (queue, log bookmarks)
  systemd/monitoring-otelcol.service, monitoring-netconn.service   (linked into /etc/systemd/system)
  netconn/                       optional TCP-connections-per-port helper
  backup/<timestamp>/            before every apply
  VERSION, answers.yaml          what produced this install (answers without secrets)
```

Collector start: `--config config.yaml --config host.yaml [--config site.d/…]`
(maps merge, **lists replace**: the generator always writes full pipeline receiver lists).
Later (v2) profiles may move to `config/profiles/<name>.yaml` when the base grows too large.

---

## 6a. Defaults (an installation should finish with Enter, Enter, password)

Every prompt has a default; a default is used **silently** when it can only be one value, and shown with
`[default]` when the operator might want something else. Only secrets have no default.

| Item | Default | Changed by |
|---|---|---|
| Install path | `/opt/monitoring` | `--prefix` |
| Collector user | `otelcol-contrib` (system user, no shell, no admin groups) | `--user` |
| systemd units | `monitoring-otelcol`, `monitoring-netconn` | not configurable (one name everywhere) |
| Collector version | the one pinned in the release (sha256) | `--collector-version` (must be in the release's list) |
| Services to enable | every finding with confidence `high` or `medium` | prompt "Enable […]?" Enter = yes, or `--only` / `--skip` |
| Backend preset | `openobserve` | answers / prompt |
| Backend endpoint | last used value on this host, else asked once | answers / prompt |
| Oracle service name | derived from the SID (`ora_pmon_<SID>`, lower case) | prompt `[orcl]` |
| Oracle monitoring user | `otel_mon` | prompt `[otel_mon]` |
| Tomcat / JMX | JMX exporter port from the `-javaagent` argument, else 9404 | prompt only if not found |
| Log files | detected paths (alert log, Tomcat `logs/`), `start_at: end` | prompt only if not found |
| HTTP checks | none, except Tomcat: `http://127.0.0.1:<port>/` | answers / prompt (optional) |
| Collection interval | 60 s metrics, 30 s session snapshots, 300 s heavy queries | site overlay |
| TCP connections helper | on, ports = the enabled services' ports | host.env `NETCONN_PORTS` |
| Batching, queue, memory limit | `file_storage` queue, `memory_limiter` 600/150 MiB | site overlay |

**Finishing in one run:** after a clean plan (validate VALID, smoke run 0 errors) the interactive installer
asks `Apply now? [Y/n]`. With failures it never asks. Without a terminal (`--non-interactive`, automation)
nothing is applied unless `apply` is given. The plan and the diff are always shown before the question.

```
$ curl -fsSL …/get.sh | sudo bash
found  oracle (1521, ORCL) · tomcat (8080, JMX 9404) · redis (6379)
Enable [oracle, tomcat, redis]? [Y/n]
Backend endpoint [https://backend.example.com/api/<org-id>]:
Auth header (hidden):
Oracle service name [orcl]:
Oracle monitoring user [otel_mon]:
Oracle monitoring password (hidden):
validate VALID · smoke run: 8 receivers started, 0 errors · NEW 7 files
Apply now? [Y/n]
active · first data sent · done
```

---

## 7. Rule catalog (detection)

One YAML file per service, shipped in the binary (embedded), unit-tested with fixtures.

```yaml
# rules/oracle.yaml
id: oracle
profile: oracle                        # the oracle part of config.yaml, switched on by ORACLE_MON=on
detect:
  any:
    - port: 1521
      process: [tnslsnr]
    - process_regex: '^ora_pmon_(?P<sid>\w+)$'
derive:
  sid: '{{ .match.sid }}'
  oracle_base: '{{ env_of "ora_pmon_*" "ORACLE_BASE" | default "/u01/app/oracle" }}'
  alert_log: '{{ glob (printf "%s/diag/rdbms/*/%s/trace/alert_%s.log" .oracle_base .sid .sid) }}'
ask:
  - key: ORACLE_SERVICE
    prompt: Oracle service name
    default: '{{ .sid | lower }}'
  - key: ORACLE_MON_USER
    prompt: Oracle monitoring user
    default: otel_mon
  - key: ORACLE_MON_PASSWORD
    prompt: Oracle monitoring password
    secret: true
read_access:                            # single files, ACL u:<collector user>:r
  - '{{ .alert_log }}'
switches:
  ORACLE_MON: 'on'
docs:
  sql: sql/oracle-grants.sql            # printed by `amc sql oracle`, run by a DBA
```

---

## 8. CLI

```
amc plan      [--answers F] [--secrets-file F] [--only a,b] [--skip c]   # default command, read-only
amc apply     [--start] [same flags] [--yes]                              # changes the system
amc detect    [--json]                                                    # findings only
amc sql <profile>                                                         # print DB grants
amc uninstall [--keep-secrets]
amc version
Global: --non-interactive (fail instead of asking), --release <tag>, --root <dir> (tests), --verbose
Exit codes: 0 ok · 1 plan has failures · 2 usage · 3 verification (signature / checksum) failed
```

---

## 9. Answers file (no secrets)

```yaml
# answers.yaml: everything the prompts would ask, except secrets
backend:
  preset: openobserve
  endpoint: https://backend.example.com/api/<org-id>
services:
  oracle:  { enabled: true, ORACLE_SERVICE: orcl, ORACLE_MON_USER: otel_mon }
  tomcat:  { enabled: true }
  redis:   { enabled: false }
checks:
  http: [http://127.0.0.1:8080/app/]
```

---

## 10. Secrets

- Read from: `--secrets-file` (0600, owned by root) → environment → hidden prompt from `/dev/tty`.
- Written as `KEY='value'` to `secrets/collector.env` (0600 root); values with `'` or a newline are rejected.
- Never in argv, URLs, logs, the answers file, the diff output or any bundle.
- Values that a YAML parser could retype (e.g. digits-only passwords) are always injected as strings
  (section 13).

---

## 11. Security model

| Threat | Control |
|---|---|
| Tampered download (mirror, CDN, MITM) | minisign signature over `SHA256SUMS`, public key embedded in `get.sh`; sha256 per asset |
| Compromised release pipeline | signing key outside CI (or keyless cosign + transparency log as an option); reproducible builds |
| Truncated `curl \| bash` | `main()` wrapper; documented alternative: download, read, run |
| Secrets leaking | section 10; collector logs never contain secrets; `--verbose` redacts known keys |
| Over-privileged collector | own system user, no admin groups (e.g. never `dba`/`oinstall`), single-file ACLs, systemd sandbox (`ProtectSystem=strict`, `ReadWritePaths=data/`, `NoNewPrivileges`) |
| Wrong config breaks monitoring | plan (validate + smoke run) before apply; backup + automatic rollback |
| Database load / licence | profile SQL kept light; no licensed views (e.g. Oracle ASH/AWR = Diagnostics Pack) |

---

## 12. Testing

- **Unit:** each rule against fixtures (fake `/proc` trees, process lists, files) → expected findings.
- **Golden files:** fixed answers → byte-identical `host.yaml` / `host.env`.
- **Collector smoke run in CI:** pinned collector, fake listeners on the discovery ports, digits-only fake
  password; every receiver must start.
- **Canary:** known collector behaviour (e.g. int-typed passwords) is tested so an upgrade that changes it is
  noticed.
- **End-to-end:** `get.sh` against a local web server; a tampered asset must be refused.
- **Distro matrix:** containers for each OS in section 2 run `detect` + `plan`.
- **Acceptance for the migration (section 14):** on the first two real hosts the generated files must equal
  the hand-written ones (`compare_configs`: NO DIFFERENCES).

---

## 13. Lessons carried over (each one cost a debugging session)

- `validate` does **not** build `receiver_creator` templates. A digits-only password became an `int` there and
  all database receivers failed while `validate` said VALID → smoke run + string injection
  (`"${env:X}${env:FORCE_STRING:-}"`; quotes and `!!str` do not help).
- Templated `resource_attributes` in `receiver_creator` silently stop the receiver → keep them static.
- A literal `$` in collector config is `$$`.
- Config merge: maps merge, lists replace → generate full pipeline lists.
- Windows line endings break shell scripts and configs → LF enforced in CI.
- `caddy validate` / collector `validate` as root can create files owned by root that the service user then
  cannot open → validate as the service user.
- A fake TCP listener that never answers can hang the collector's shutdown → `timeout -k`.
- Behind a reverse proxy, trust `X-Forwarded-For` only from the proxy and read it right-to-left.

---

## 14. Phases and acceptance criteria

| Phase | Delivers | Done when |
|---|---|---|
| 1. Foundations | public repo, license, this document, Go module, CI skeleton | CI green on an empty build |
| 2. Generic parts | base config, profiles host/oracle/tomcat/redis/caddy, install engine in Go | `plan` on a test VM = today's install result |
| 3. Detection | rule catalog + `detect` + `plan` | on 2 real hosts: generated files = current files (NO DIFFERENCES) |
| 4. Releases | signed releases, `get.sh` | tampered asset refused; one-liner works from GitHub |
| 5. Switch hosts | operator's private repo holds only answers files; same path / unit / file names, so a host switches with one `plan` + `apply` (no migration step) | every host on the new installer, old download path retired |
| 6. Extras | dashboard / alert generators per backend | optional packages, documented |

Existing installations keep running unchanged until phase 5.

---

## 15. Open decisions

| # | Question | Proposal |
|---|---|---|
| 1 | Project / repository name | **decided**: `auto-mon-collector`, binary `amc` (alias), env prefix `AMC_` |
| 2 | License | Apache-2.0 (same as OpenTelemetry) |
| 3 | Ownership | approved by the owner of the original setup (2026-10-05) |
| 4 | Signing | minisign (small, offline verify); cosign keyless as an option |
| 5 | Go version | latest stable, `CGO_ENABLED=0`; check the minimum kernel for CentOS 7 (3.10) before release (unverified) |
| 6 | Docker containers | after v1 (`docker_observer`) |
| 7 | Backend presets | OpenObserve first; generic OTLP; others by contribution |
| 8 | Install path and names | **decided**: `/opt/monitoring`, units `monitoring-otelcol` / `monitoring-netconn`, user `otelcol-contrib`, `secrets/collector.env` (same as the existing installations) |
| 9 | Finish in one run | **decided**: defaults for everything (6a) + `Apply now? [Y/n]` after a clean interactive plan |

---

## 16. Risks

| Risk | Mitigation |
|---|---|
| False detection (non-standard ports, proxies) | confidence levels, user confirms, smoke run |
| OS / database version matrix grows | containers in CI, "best effort" label for EOL systems |
| Maintenance load (issues, pull requests) | contribution guide, rule + fixture template, small core |
| Signing key loss or leak | key backup offline, documented rotation, short-lived keys via cosign as fallback |
| Users press Enter through `Apply now?` | only offered after a clean plan, diff shown first, backup + automatic rollback on failure |
