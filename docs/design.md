# auto-mon-collector: host discovery installer for the OpenTelemetry Collector

Status: **draft v0.2** (2026-10-05: default path `/opt/monitoring`, defaults table, finish in one run). Name, license and repository are decided in section 15.
This document is written to become the first commit of a **public** repository: it contains no data about any
real host, network or company. Examples use generic values (`ORCL`, `/u01/app/oracle`, `backend.example.com`).

---


> **Names** (one standard since v0.20.0: everything that runs is `monitoring-*`): the installer / agent binary
> `monitoring-agent` (`bin/monitoring-agent`), Cloudprober = `monitoring-prober` (unit, `bin/monitoring-prober`,
> `config/prober/prober.cfg` + `targets-*.json`), `state.json`, `.monitoring.lock`, polkit `50-monitoring-agent.rules`,
> release assets `monitoring-agent-linux-*`, `keys/release.pub`, Unix users `monitoring` (collector + prober; was
> `otelcol-contrib` before v0.21.0, still moved by an apply) and `monitoring-agent`. Older names below are history;
> data names (metrics `cloudprober_*`, streams) stay. The product's old short name and its compatibility were dropped
> after v0.23.1: supported hosts start at v0.21.0.
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
| Collector | `monitoring-collector` (OCB build in `collector/`, since v0.19.0) from the same signed release as monitoring-agent; before: `otelcol-contrib`, version + SHA-256 pinned |
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
get.sh ──▶ download installer ──▶ verify signature + sha256 ──▶ monitoring-agent plan  (default, read-only)
                                                                    │
     detect ─▶ propose ─▶ ask ─▶ generate (to a staging dir) ─▶ validate + smoke run ─▶ show diff
                                                                    │
                                                    monitoring-agent apply [--start]  (only on request)
                                                                    │
                     install binary ─▶ backup ─▶ write files ─▶ ACLs / SELinux ─▶ systemd ─▶ start ─▶ check
```

### 4.0 Before the first run (by hand, once)
- Database monitoring user + grants (SQL printed by `monitoring-agent sql oracle`, run by a DBA).
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
| Auth header | secrets file → env `MONITORING_OO_AUTH` → hidden prompt |
| Oracle service name | answers → derived from SID / listener config → prompt with the guess as default |
| Oracle monitoring user / password | answers (user) → hidden prompt (password) |
| HTTP checks (URLs) | answers → prompt (optional, empty = none) |
| Project (v0.3.0) | answers → prompt, default = the previous answer, `-` = none |
| Tomcat access log / Tomcat log (v0.3.0) | answers → scan (default name, renamed `*access*log*`, `catalina.out`, else daily `catalina.*.log` + `localhost.*.log`) → prompt with the scan result as default, `-` = none. Nothing found and nothing answered = a `DEFAULT` line in `plan` (logs never go missing silently) |

### 4.5 Generate (staging, still read-only for the system)
Writes to a staging directory: `host.yaml`, `host.env`, `collector.env` (0600), plus the shipped base config
(`config.yaml`, all profiles inside, switched by `host.env`). Output is sorted and stable.

### 4.6 Validate
1. `monitoring-collector validate` (before v0.19.0: `otelcol-contrib validate`) with the staged files and the real binary (downloaded to the staging dir if the
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
- **Update (v0.10.0):** `get.sh | sudo bash -s -- update`. Inputs come from the installation itself:
  `<prefix>/answers.yaml` (written by every `--answers` / interactive apply) and the installed `config/site.d/`
  (kept as is; since v0.27.2 `plan` / `apply` without `--site-dir` keep it too, `--site-dir none` removes it). Scan again, check run (validate + smoke);
  only after a clean check that changes something: apply + start + rollback (no second smoke run). An
  up-to-date host is NOT restarted (a restart resets cumulative counters). `--plan` stops after the check.
  v0.10.1: only `VERSION` differs (a new installer, identical configuration) = apply WITHOUT start (VERSION
  written, the running collector already has this configuration). v0.15.0: the same for `inventory.json`
  (`Result.NoRestart`: only files no unit reads changed).
  No answers.yaml (install via `--host-dir`) = stop with exit 2. Changing answers / site.d is still
  `plan` / `apply --answers F [--site-dir D]`. The engine reports `Result.Changes` (check mode: "would"
  actions + changed files) for this decision.
- **Many hosts:** `--answers hosts/<name>.yaml --secrets-file /root/monitoring.secrets --yes` (answers files
  live in the operator's private repository; secrets file put on the host by the operator or a vault agent).
- **Removal:** `monitoring-agent uninstall` (units, files; secrets only after an explicit confirmation).

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
  bin/monitoring-collector       the collector of this monitoring-agent release (v0.19.0+; before: bin/otelcol-contrib)
  bin/monitoring-agent           installer (auto-mon-collector) (for updates / plan / uninstall)
  config/
    config.yaml                  layer 1: shipped base, same everywhere: runtime discovery + all service
                                 profiles, each switched on/off in host.env (v1: profiles live in the base)
    host.yaml                    layer 2: generated (static receivers: log files, checks; full pipelines)
    site.d/*.yaml                layer 3: optional operator overlay (never touched by the installer)
    host.env                     switches, no secrets
  secrets/collector.env          0600 root, never printed, never in a bundle or repo
  data/                          the only writable dir (queue, log bookmarks)
  systemd/monitoring-collector.service   (linked into /etc/systemd/system; before v0.19.0: monitoring-otelcol +
                                 the helper units netconn / kmsg / procs / sshd with scripts in netconn/)
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
| systemd units | `monitoring-collector` (v0.19.0+; before `monitoring-otelcol` + 4 helpers) | not configurable (one name everywhere) |
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
| TCP connections (`netconn` receiver) | on, ports = the enabled services' ports | host.yaml `receivers.netconn.ports` (v0.19.0; before host.env `NETCONN_PORTS`) |
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
  sql: sql/oracle-grants.sql            # printed by `monitoring-agent sql oracle`, run by a DBA
```

---

## 8. CLI

```
monitoring-agent plan      [--answers F] [--secrets-file F] [--only a,b] [--skip c]   # default command, read-only
monitoring-agent apply     [--start] [same flags] [--yes]                              # changes the system
monitoring-agent update    [--plan] [--detect-json F]                                  # saved answers + installed site.d
monitoring-agent self-update --request F [--prefix D]                                  # root, v0.16.0: signed request from the agent (section 17)
monitoring-agent detect    [--json]                                                    # findings only
monitoring-agent sql <profile>                                                         # print DB grants
monitoring-agent uninstall [--keep-secrets]
monitoring-agent version
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
  redis:   { enabled: false }           # v0.33.0: + port; locked: true = never switched on by the control plane
  nginx:   { enabled: true, port: 80, status_path: /nginx_status }   # v0.33.0: stub_status, off unless enabled
checks:
  http: [http://127.0.0.1:8080/app/]
  tcp:                                  # v0.11.0: connect checks to other hosts
    - endpoint: db.example.com:1521
      comment: Oracle primary
probes:                                 # v0.12.0: Cloudprober probes from this host (optional)
  interval_s: 30                        # 10-3600, default 30
  tcp:
    - {name: db_primary, host: db.example.com, port: 1521}
  http:
    - {name: payments_api, url: "https://api.example.com/health"}
  ping:
    - {name: gateway, host: 192.0.2.1}
```

`probes` (v0.12.0): active probes run by [Cloudprober](https://github.com/cloudprober/cloudprober) (Apache-2.0), a
second small agent next to the collector. Empty = Cloudprober is not installed; removing all probes later stops,
disables and unlinks its unit and removes its files (the binary stays until `monitoring-agent uninstall`).
- Install: pinned v0.14.6 (`internal/cloudprober`, release tarball checked against the pinned SHA-256, only the
  binary is extracted) -> `bin/cloudprober`; `config/cloudprober.cfg` (generated) + `config/cloudprober-tcp.json`
  (file targets, re-read every 30 s: the agent changes the list without a restart); ping = one probe per target with
  fixed labels (v0.14.0, see below);
  unit `monitoring-cloudprober` (collector user, sandboxed, `MemoryMax=150M`; `CAP_NET_RAW` only when there are ping
  probes: raw ICMP socket, `net.ipv4.ping_group_range` is not touched). `plan` runs `cloudprober --configtest`.
- Metrics: Cloudprober listens on `127.0.0.1:9313` only; the collector scrapes it (`prometheus/cloudprober`, interval =
  `interval_s`) and keeps `cloudprober_total`, `_success`, `_failure`, `_timeouts`, `_latency` (cumulative
  MICROseconds of the successful probes), `_resp_code{code}`, `_ssl_earliest_cert_expiry_sec`. Labels: `probe`
  (`tcp`, `ping_<name>`, `http_<name>`), `dst` (`host:port` / host), `target` (the name above; keep names stable, they
  are labels), `path` (v0.14.0, only when a probe sets it).
- Names: `a-z 0-9 _`, unique over all probes. Hosts: a DNS name or an IP; URLs: http(s) without credentials. Loopback
  targets are allowed (unlike `checks.tcp`). Not asked interactively; an interactive run or `monitoring-agent update` keeps them.
- PromQL: up (share of successful probes) = `increase(cloudprober_success[5m]) / increase(cloudprober_total[5m])`;
  average latency in ms = `rate(cloudprober_latency[5m]) / rate(cloudprober_success[5m]) / 1000`; TLS days left =
  `cloudprober_ssl_earliest_cert_expiry_sec / 86400`.
- v0.13.0: Cloudprober's files live in `config/cloudprober/` (own directory: the agent may replace exactly these files);
  v0.12.0 files directly in `config/` are removed on the next apply (`REMOVE config/cloudprober.cfg`).
- v0.22.3: every http probe has a status validator (`http_validator { success_status_codes: "200-399" }`): before it,
  Cloudprober counted ANY HTTP answer as success (a 404 / 502 was "up"; tested on v0.14.6). A 4xx / 5xx answer now
  counts as a failure (`cloudprober_validation_failure`); CI e2e checks it with a 404 probe.
- v0.14.0: optional `path: private | public | other` per tcp / http / ping probe (answers or the agent's list) = which
  address of a peer is checked (a mesh "strand": the same peer over its private and its public address). It becomes
  the metrics label `path` (tcp: file-target label + `additional_label`; http / ping: a fixed `additional_label`);
  without any `path` the config and the metrics are exactly as before. A control plane may send `path` only to agents
  >= v0.14.0: older agents refuse unknown fields.
- v0.14.0: ping = one Cloudprober probe per target (`ping_<name>`) with FIXED `target` / `path` labels. Before, all
  pings shared one probe with file targets, and Cloudprober drops a file target's labels when its DNS name does not
  resolve ("Bad target") -> `target=""` (tested with Cloudprober v0.14.6). The probe label changes `ping` ->
  `ping_<name>`; `target` is unchanged.

`checks.tcp` (v0.11.0): TCP connect checks from this host to OTHER hosts (`host:port`, `[IPv6]:port`), e.g. the
database or the next hop of a request path, so a dashboard can show the state of each link. One `tcp_check` receiver
holds them together with the local Oracle listener check: metrics `tcpcheck.status` (1 = connected),
`tcpcheck.duration` (ms), attribute `tcpcheck.endpoint` = the endpoint as written. Loopback targets are refused, so the
listener stays the only `127.0.0.1:` endpoint: consumers that mean "the listener" filter on that prefix (a neighbour on
`:1521` must not look like a local listener). Not asked interactively; an interactive run or `monitoring-agent update` keeps the list.

`project:` (optional, since v0.2.0): a group name (1-64 characters `A-Z a-z 0-9 space . _ -`). monitoring-agent writes
`OTEL_RESOURCE_ATTRIBUTES=project=<url-encoded>` into `host.env`; the `env` detector of `resource_detection` turns it
into the resource attribute `project` on every metric, log and span of the host. Asked interactively since v0.3.0
(default = the saved answer). The base config also collects `system.uptime` (host_metrics `system` scraper).

`host_name:` (optional, since v0.22.4): the `host.name` the host reports instead of the OS hostname (a VM named
`docker`, `localhost` ...): lower-case DNS labels joined by dots. It goes into the same `OTEL_RESOURCE_ATTRIBUTES`
(`project=...,host.name=...`); the `env` detector runs before `system` and the first detector wins a key, so it
replaces the OS name. Changing it starts a new series in the backend (old data keeps the old name).

v0.22.4: an EXISTING prefix / bin / config directory without r-x for others gets it added (`chmod`): a prefix made
700 by hand before the first install made the collector fail with 203/EXEC.

`services.tomcat.access_log` / `services.tomcat.logs` (optional, since v0.3.0): absolute file globs (`*` = any date)
when the scan cannot find the files or finds the wrong ones; `-` = none. Empty = what the scan found. The
interactive run saves them only when they differ from the scan, so a later scan still follows moved files.
`services.oracle.cdb_service` (optional, since v0.4.0): the CDB root service (e.g. `orcl`). Needs a COMMON
monitoring user (`C##...`, the same user and password for the PDB and the root; asked only for such a user). Adds
`sql_query/oracle_cdb` (60 s): `oracle.pdb.open` per PDB (1 = READ WRITE and not restricted; attributes pdb,
open_mode, restricted), `oracle.database.state` (attributes role, open_mode, cdb = YES / NO since v0.8.0), `oracle.limit.current` / `.max`
(processes, sessions: `V$RESOURCE_LIMIT` is empty inside a PDB), `oracle.fra.limit` / `.used` / `.reclaimable`.
Root grants: `V_$PDBS` (with `CONTAINER_DATA`), `V_$DATABASE`, `V_$INSTANCE`, `V_$RESOURCE_LIMIT`,
`V_$RECOVERY_FILE_DEST`. Only the root sees a PDB that is MOUNTED.

`services.oracle.non_cdb` (optional, since v0.8.0): `true` = a NON-CDB database (no PDBs, no CDB root). Adds
`sql_query/oracle_db` (60 s) against the database service itself with the normal (local) monitoring user: the same
`oracle.database.state`, `oracle.limit.current` / `.max` and `oracle.fra.*` as `oracle_cdb` (`V$RESOURCE_LIMIT` works
in a non-CDB), without `oracle.pdb.open`. Grants: `V_$DATABASE`, `V_$RESOURCE_LIMIT`, `V_$RECOVERY_FILE_DEST`.
Excludes `cdb_service` and a common user. Asked interactively for a local user (`Non-CDB database?`, default = the
saved answer, else no).

**v0.19.0: one collector, no helpers.** Everything in the next three paragraphs (and the netconn helper) now runs inside
`monitoring-collector`: receivers `netconn` (reads `/proc/net/tcp{,6}`) and `procs` (two `/proc` snapshots 15 s apart,
command names only, `/proc/<pid>/cmdline` is never read), and the stock `journald` receiver twice in
`config/journal.yaml` (kernel `--dmesg` priority warning+, sshd `--identifier sshd --identifier sshd-session`). Same
streams and attributes. **Privilege change (accepted):** the collector unit gets the group `systemd-journal`, so the
process can read the whole journal; what leaves it is fixed in the shipped file (not in answers / site / remote
config): only MESSAGE (+ PRIORITY) survives the receiver, `transform/sshd` is the FIRST processor of the ssh pipeline
and masks everything between "invalid user" and the address (the old sed rule let names with spaces through), before
the disk queue. `collector/test/journal` runs the real receiver + processor against golden files in CI. The journald
receiver follows the journal (`journalctl --follow`, cursor in `file_storage`); CI rotates the journal and checks
that new lines still arrive. History of the helpers below.

**Kernel messages (v0.5.0, every host):** unit `monitoring-kmsg` runs `netconn/otel-kmsg.sh`: `journalctl -k -p warning
-o json`, polled every 10 s with a cursor (kernel only, warning or worse, no history) -> `data/kmsg/kmsg-<day>.jsonl` (2 days) -> `file_log/kmsg`
-> stream `kernel`, attribute `kind` = oom / hung_task / disk_error / other. Least privilege: only this unit has the
supplementary group `systemd-journal`; the collector process cannot read the journal (checked in CI). Sandboxed like
netconn (`ProtectSystem=strict`, `PrivateNetwork=yes`, no capabilities, `MemoryMax=32M`).

**Top processes (v0.6.0, every host):** unit `monitoring-procs` runs `netconn/otel-procs.sh --loop 60`: two `ps`
snapshots 15 s apart -> one JSON line per process in the top 10 by CPU (over the 15 s, 100 = one core) or top 10 by
RSS: pid, user, comm, rss_kb, cpu_pct, etime_s, top -> `data/procs/procs-<day>.jsonl` (mode 640, 2 days) ->
`file_log/procs` -> stream `processes`. Command names only, never arguments (they can hold passwords). Chosen over
the hostmetrics `process` scraper: ~20 rows per minute per host instead of one time series per process (short-lived
processes would create new series all the time). No root, no network, no capabilities.

**SSH logins (v0.7.0, every host):** unit `monitoring-sshd` runs `netconn/otel-sshd.sh`: `journalctl -t sshd -t
sshd-session`, polled every 10 s with a cursor (sshd's own messages only, no history), keeps only login lines (accepted, failed, invalid
user, connection closed / disconnected before auth, PAM session opened / closed) -> `data/sshd` -> stream `ssh`,
attributes event / user / src_ip / method. **Privacy:** the name of an UNKNOWN user is replaced by `***` before it is
written (people type their password into the user field); sudo and all other services are never read. Journal access
only in this unit and `monitoring-kmsg`.
Both journal helpers POLL with a cursor (`--after-cursor`, position in `data/<helper>/.cursor`) instead of `journalctl
-f`: a long-running follower missed lines after the journal changed under it (found in CI); polling opens the journal
fresh each time, survives rotations and loses nothing across a helper restart. CI rotates the journal and checks both.

**HTTP metrics from the access log (v0.9.0, every host with an access log):** the access-log receiver also feeds
the pipeline `logs/http_metrics` -> connector `signal_to_metrics/http` -> `metrics/http` (processor `delta_to_cumulative`:
the connector emits per-batch deltas, PromQL `rate()` needs cumulative counters) -> the metrics backend.
`tomcat.access.requests` (sum; attributes `status_class` = first digit of the status, `method`), `tomcat.access.duration`
(histogram, ms, buckets 25 .. 30000; only lines with a duration), `tomcat.access.logins` (sum by `status_class`, only with
`services.tomcat.login_path` = a regular expression of the login path; letters, digits and `^$/._*+?()|[]-` only, it is
put into an OTTL string). The access log keeps flowing to the logs backend unchanged (new field `status_class`).
CI: real collector, access-log lines in, counters (cumulative, accumulating) and histogram out.
Names `tomcat.access.*` since v0.9.1: an application with the OpenTelemetry Java agent sends its own `http.server.*`
metrics (seen: `http_server_requests_bucket` from the app next to ours in the backend). Checked on a real host:
the backend stores the histogram Prometheus-style (`_bucket{le}`, `_sum`, `_count`), `histogram_quantile` works.

**Oracle Data Guard + backups (v0.9.0, answers):** `services.oracle.data_guard: true` -> `sql_query/oracle_dg` (60 s):
`oracle.dataguard.lag` seconds, attribute `kind` = apply_lag / transport_lag (V$DATAGUARD_STATS; on the standby the
monitoring user must be able to log in = Active Data Guard / read only; NULL = -1). `services.oracle.backups: true` ->
`sql_query/oracle_backup` (300 s): `oracle.backup.age` hours since the last COMPLETED job per `type` (DB FULL, DB INCR,
ARCHIVELOG, ...), `oracle.backup.failed_24h`. Both run against the CDB root when `cdb_service` is answered, else the
service. Grants: `V_$DATAGUARD_STATS`, `V_$RMAN_BACKUP_JOB_DETAILS`. Not checked against a real database yet:
the time base of SYSDATE vs END_TIME (verify on the first host).

**Oracle capacity (v0.22.0, answers):** `services.oracle.capacity: true` -> `receiver_creator/capacity` with
`sql_query/oracle_capacity` (6 h) and `sql_query/oracle_capacity_files` (24 h: `DBA_EXTENTS` for the high-water
marks), against the service itself (DBA_ views are per container), log stream `oracle_capacity`, attribute `kind`:
`table` (top 50 tables, segments folded into the owning table: data / index / LOB bytes, rows from statistics, plus
one `(others)` row), `tablespace` (allocated, free inside the files, autoextend max), `partition_waste` (partitioned
tables with many segments for few rows; partition segments start at 8 MB), `recyclebin`, `file` (size, autoextend, max) and `file_hwm` (high-water
mark, `reclaim_b` = what a RESIZE could give back; own query, 900 s scrape timeout). v0.22.1: tablespace used / free from
`DBA_TABLESPACE_USAGE_METRICS` (`DBA_FREE_SPACE` and `DBA_EXTENTS` were too slow for the monitoring user on a real PDB). Growth = difference between snapshots, computed by the reader.
Oracle-maintained schemas are left out. Grants: single DBA_ views (listed in the config comment), no Diagnostics Pack.
**More PDBs (v0.31.0):** `services.oracle.capacity_pdbs: [<service>, ...]` (at most 3, needs `capacity: true`, not on a
non-CDB) runs the same two query lists (YAML anchors `capacity_queries` / `capacity_files_queries`) in each extra PDB:
receivers `sql_query/oracle_capacity_pdb<n>` and `sql_query/oracle_capacity_files_pdb<n>` (n = 2..4), switched on by
`ORACLE_CAPACITY_PDB<n>` in host.env. Records carry `container` = that PDB. The capacity grants are needed inside each PDB.

`services.tomcat.time_zone` (optional): zone of the times in Tomcat's own log (they carry no offset). Default: the
JVM's zone from the scan (`-Duser.timezone`, else the process's `TZ`), else the host's zone. A JVM in another zone
than the host would otherwise put every entry hours off.

```yaml
services:
  tomcat:
    access_log: /opt/tomcat10/logs/access_log.*.log
    logs: [/opt/tomcat10/logs/catalina.*.log, /opt/tomcat10/logs/localhost.*.log]
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
| Tampered download (mirror, CDN, MITM) | ECDSA P-256 signature over `SHA256SUMS` (openssl: present on every target incl. CentOS 7 / OpenSSL 1.0.2; minisign is not installed on RHEL-family hosts), public key embedded in `get.sh`, checked against the committed key before each release; sha256 per asset; no openssl = no run |
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
| 1 | Project / repository name | **decided**: `auto-mon-collector`, binary `monitoring-agent` (since v0.20.0), env prefix `MONITORING_` |
| 2 | License | Apache-2.0 (same as OpenTelemetry) |
| 3 | Ownership | approved by the owner of the original setup (2026-10-05) |
| 4 | Signing | **decided**: ECDSA P-256 with openssl (no extra tool on the hosts); key in the GitHub Actions secret AMC_SIGNING_KEY (option A, 2026-10-05); public key keys/release.pub |
| 5 | Go version | latest stable, `CGO_ENABLED=0`; check the minimum kernel for CentOS 7 (3.10) before release (unverified) |
| 6 | Docker containers | after v1 (`docker_observer`) |
| 7 | Backend presets | OpenObserve first; generic OTLP; others by contribution |
| 8 | Install path and names | **decided**: `/opt/monitoring`, unit `monitoring-collector` (v0.19.0; before `monitoring-otelcol` + helpers), user `otelcol-contrib`, `secrets/collector.env` (same as the existing installations) |
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

---

## 17. Agent (v0.13.0): probe lists from a control plane

v0.14.0 changes: (1) after the FIRST 401 the agent retries once after 12 s with a new request (fresh nonce) before
its backoff (up to 5 min): right after a control-plane restart a proxy can re-send the open long poll with the SAME
nonce -> "nonce reused"; (2) probes may carry `path` (see 9); (3) backup / rollback copies keep owner, setgid and the
exact file mode (a rollback restored `config/cloudprober` as a plain root 0775 directory: the agent could no longer
replace its files until the next apply).

`monitoring-agent agent` lets a control plane (for example a monitoring wall where an admin draws a link and answers "what to
observe?") change the PROBES of a host within seconds, without SSH and without `monitoring-agent apply`. The idea is the one of
tunnel agents: the agent dials out, the host opens no port.

**What it can do, and what never.** It accepts one thing: a signed list of probes (tcp / http / ping, the same schema
and rules as `probes:`). It never runs commands, never writes a path it gets from the control plane, never installs or
updates software (that stays `monitoring-agent apply` / `monitoring-agent update`, signed releases), never touches the collector, secrets,
ACLs, SELinux or other units. One exception since v0.16.0, off by default: it may hand a signed "update monitoring-agent to
release X" request to root (see "Remote update" below); root checks everything again.

**Host owner first.** `answers.yaml` (root) decides:

```yaml
agent:
  url: https://agent.example.com/agent/            # https only (http only for 127.0.0.1 / localhost: tests, tunnels)
  control_plane_key: "ed25519:<base64>"            # the ONLY key that may sign probe lists (pinned here)
  allow:                                           # host extras, added to the project template (--agent-allow)
    domains: ["*.example.com", "api.example.org"]  # exact names or *.suffix (any depth); names are not resolved
    networks: ["192.0.2.0/24"]                     # IP targets must be inside; empty = no IP targets
    ports: [443, 5432]                             # tcp ports and http(s) URL ports (80 / 443 when not written)
    max_probes: 30                                 # default 30 (max 100)
    min_interval_s: 15                             # default 15
    ping: false                                    # true = ping allowed (the Cloudprober unit gets CAP_NET_RAW)
```

Project template: `plan` / `apply --agent-allow FILE` (same keys as `allow`, unknown keys are errors) installs it as
`config/agent-allow.yaml` (root 644); `update` keeps the installed one, and since v0.22.5 so do plan / apply without
the flag (before, they removed it and the agent dropped every probe outside the host extras); `--agent-allow none`
removes it. Effective list = template + host extras: lists joined, a number set on the host replaces the
template's, ping allowed when either allows it. `plan` prints it (`agent allowlist: ...`).

**Install** (`apply` with an `agent:` section): user `monitoring-agent` (system, no shell, no groups), `<prefix>/agent/`
(monitoring-agent 700: key + state), `bin/monitoring-agent` (a copy of the monitoring-agent that ran the apply; `update` replaces it), unit
`monitoring-agent` (monitoring-agent, `NoNewPrivileges`, `ProtectSystem=strict`, writes only `<prefix>/agent` and
`config/cloudprober/`, no capabilities, `MemoryMax=200M`), `config/cloudprober/` owned root:monitoring-agent with setgid
2775, and `/etc/polkit-1/rules.d/50-monitoring-agent.rules`: monitoring-agent may `restart` `monitoring-cloudprober.service`,
nothing else (no polkit on the host = a warning; target-only changes still work, config changes wait for an apply).
Cloudprober then always runs (with an empty config until the first list). Everything is in `state.json`; the
agent removed from the answers = unit stopped + unlinked, polkit rule removed (key and state stay until uninstall);
`uninstall` removes the agent dir, the polkit rule and the user.

**Enrol** (once, root): the control plane shows a one-time token; on the host
`sudo monitoring-agent agent enrol --token-stdin` (typed or piped, never an argument). The agent key (Ed25519) is created on the
host, only its public key is sent; the file is written (monitoring-agent 600) only after the control plane accepted it. The
agent picks it up within 15 s.

**Protocol** (`internal/agent/protocol.go` has the exact wire format):
- `POST <url>v1/enrol {"host","token","public_key"}` (no signature).
- Every other request is signed with the host key: headers `X-Mon-Host`, `X-Mon-Time` (unix s, ±120 s),
  `X-Mon-Nonce`, `X-Mon-Signature` = Ed25519 over the lines `METHOD`, `REQUEST-URI`, `time`, `nonce`,
  `hex(sha256(body))` joined with `\n`. TLS ends at a proxy in many setups, so client certificates would not reach the control plane: signatures work through
  any proxy.
- `GET <url>v1/desired?have=N`: long poll (200 = newer signed document, 204 = nothing newer).
- `POST <url>v1/status {"revision","result":"applied|rejected|error","detail","versions"}`.
- v0.15.0: `POST <url>v1/inventory {"versions","revision","inventory","inventory_error"}`: at start and whenever the
  body changes (a new revision applied, a new inventory.json after `monitoring-agent update`). `inventory` = `<prefix>/inventory.json`
  compacted (`null` + `inventory_error` when missing / larger than 48 KiB / not JSON). A 4xx (404 = a control plane
  without the endpoint) is not retried until the body changes; other errors are retried with the next poll.
  inventory.json (schema 1, root 644, written by plan / apply / update as root: the agent cannot read other users'
  processes): `{"schema", "os", "services": [{"id", "monitored", "ports", "http_port", "instances" (Oracle SIDs),
  "apps" (Tomcat context paths)}], "listen": [{"ip", "port", "service"}], "truncated"}` (max 256 sockets). An
  allowlist of fields: no file paths, environment, pids or time stamps, so an unchanged host gives the same bytes.
  The scan runs at plan / apply / update only: a service started later shows up after the next `monitoring-agent update`.
- Document `{host, revision, issued_at, expires_at, probes, sig}`; `sig` = Ed25519 (control-plane key) over the
  canonical JSON of the received document without `sig` (keys sorted by bytes, no whitespace, no HTML escaping,
  numbers as received). Shared test vectors: `testdata/agent/canonical.json`.

**Apply rules.** A list is applied only when: signature valid with the PINNED key (the key a control plane sends at
enrolment is ignored), host = this host, revision > the applied one, not expired, the probe rules pass (the answers'
own probes + the list: names unique), the list-wide allowlist limits pass (probe count, interval), and
`cloudprober --configtest` passes on a staged copy. v0.27.0: a single probe outside the allowlist (target, port, ping) is
left out and reported in the status (`refused: [{name, reason}]`, detail "n left out (allowlist)"); the rest of the
list, and an update or overlay in the same document, go on (before, one such probe made the agent refuse it all).
Then target files, then the config; Cloudprober restarts only when its config changed (target files are re-read).
Otherwise the last good list stays and the reason is reported (`rejected` / `error`). Network errors: backoff with
jitter up to 5 min; the control plane down = probes keep running. `<prefix>/agent/state.json` holds the applied list:
`plan` / `apply` / `update` generate the same Cloudprober files from it (no drift, an apply does not undo the agent).
The collector's scrape interval comes from the answers only (a list never changes the collector config).

**Metrics**: as for `probes` (section 9); probe names chosen by the control plane are labels (`target`).

### Remote update (v0.16.0; off by default)

One action with one argument: "update monitoring-agent to signed release X". The control plane adds
`"update": {"version": "vX.Y.Z", "id": "<8-64 chars A-Za-z0-9_->"}` to a signed document (signed like the rest; an
agent before v0.16.0 rejects such a document as an unknown field, so a control plane sends it only to v0.16.0+
agents: the inventory reports their version and `update_allowed`). The host owner decides in `answers.yaml` (root);
the project template `config/agent-allow.yaml` cannot switch it on:

```yaml
agent:
  update:
    allow: false        # default: every request is refused
    downgrade: false    # default: only a release newer than the running monitoring-agent
    window: ""          # "HH:MM-HH:MM" host local time, may span midnight (e.g. "22:00-04:00"); "" = any time
```

**Agent (user monitoring-agent, not trusted with the update).** For a verified, applied document whose update id it has not
handled yet: checks `allow`, the version syntax and "no downgrade", saves the id in `agent/state.json`, writes the
WHOLE signed document to `<prefix>/agent/update-request.json` (600) and runs
`systemctl start --no-block monitoring-update.service` (polkit: monitoring-agent may `start` that unit, nothing else). It
reports `update {id, result: started | refused | failed, detail, from, to}` with the revision's status. A later
revision with the same id is not started again. Root's result (`agent/update-result.json`) is reported once in a
status `{revision (the applied one), result: "applied", update {id, result, detail, from, to}}`.

**Root (`monitoring-agent self-update --request FILE`, oneshot unit `monitoring-update`, `TimeoutStartSec=15min`, never enabled).**
Inputs: only the request file and the prefix. No URL, key, path or command comes from the request or the command line.
1. `answers.yaml` must be a root-owned plain file nobody else can write; the control-plane key and `agent.update` come
   from it. The request file is opened without following links (one link only, at most 256 KiB).
2. The document is verified again: Ed25519 signature with the pinned key, host = this host, not expired, revision
   above the last one root handled (`<prefix>/self-update.json`, root 644), an `update` with a valid id (not the last
   handled id) and version `^vMAJOR.MINOR.PATCH$`.
3. Policy: `allow`, no downgrade (unless `downgrade: true`; a non-release running build then refuses), window.
4. Lock `<prefix>/.monitoring.lock` (flock; `monitoring-agent apply` / `monitoring-agent update` take it too; the `monitoring-agent update` started below inherits
   it as fd 3, `MONITORING_LOCK_FD=3`). From here the request counts as handled.
5. Download from `https://github.com/NABIXcorp/auto-mon-collector/releases/download/<version>/` (compiled in):
   `SHA256SUMS`, `SHA256SUMS.sig` (verified first), then `monitoring-agent-linux-<amd64|arm64>` (limits 64 KiB / 1 KiB / 128 MiB,
   10 min; redirects never from https to http). `SHA256SUMS.sig` must be a DER ECDSA P-256 signature over
   sha256(SHA256SUMS) by the release key embedded in monitoring-agent (`keys/release.pub`, the same bytes get.sh checks), and the
   asset's sha256 must match its one line. Any failure: result `failed`, nothing changed.
6. Install: `bin/monitoring-agent` -> `bin/monitoring-agent.before-<old version>` (copy), the new binary written atomically (root 755); its
   `monitoring-agent version` must report the requested version, then the new `monitoring-agent update --prefix <prefix>` runs (backup, plan,
   smoke run, rollback as always). Either fails: the old binary goes back (`rolled_back`).
7. Result `<prefix>/agent/update-result.json` (root 644, written atomically: a link the agent placed there is
   replaced, not followed): `{id, from, to, result: ok | failed | rolled_back | refused, detail, at, revision}`; then
   `systemctl try-restart monitoring-agent.service` when the binary changed. A request without a verified id, or one
   handled already, does not overwrite the result file.

Threat notes: a compromised monitoring-agent can start the unit and write any request, but root accepts only a document signed
by the pinned control-plane key, for this host, not replayed, inside the owner's policy, and installs only a release
signed by the release key. A compromised control plane can at most trigger an update to a real signed release (no
downgrade unless the owner allows it). `uninstall` removes the unit link, `self-update.json` and `.monitoring.lock`.

### Collector overlays from the control plane (v0.23.0, OFF by default)

Why: a collector change on a host (drop noisy spans, mask an attribute) meant copying a site overlay and running
`plan` / `apply --site-dir` as root on every host. Why so narrow: a control plane that may send ANY collector
configuration can read any file (a `file_log` include), run commands or send all data elsewhere (an exporter). So:

- **Catalog** (`generate.CheckSite`, checked by the agent AND again by root): top level only `processors` (types
  `filter`, `transform`, `tail_sampling`) and `service.pipelines.<name>.processors` (a list of names). No receivers,
  exporters, extensions, connectors, `service.telemetry`; no `$` except `$$` (no `${env:..}` / `${file:..}`); no YAML
  anchors, aliases, merge keys or tags; one document per file. Names `cp-<a-z 0-9 _ . ->.yaml`, at most 16 files,
  64 KiB each, 128 KiB in all. Note: a pipeline's processor list may also leave out a base processor.
- **Host switch** `answers.yaml agent.site.allow: true` (root only, like `agent.update`); the inventory reports
  `site_allowed`.
- **Flow:** the signed document carries `site {revision, files}` = the control plane's COMPLETE set (empty = remove
  its overlays). The agent hands a new set revision to root with the same request file and unit as an update (one
  job at a time: a new update goes first). Root: the request again (signature, host, revision above the last one in
  `self-update.json`, which now also keeps `site_revision`), the switch, the catalog, the lock; then a staging
  directory = the host owner's installed site.d files (without `cp-`) + the new set, and `monitoring-agent update --no-fetch
  --site-dir <staging>`: plan (validate + smoke run) -> apply -> start -> automatic rollback. Result in
  `agent/site-result.json` (root 644: ok | failed | rolled_back | refused), reported once as status `site`.
- **Ownership:** `config/site.d/cp-*` belong to the control plane. `plan` / `apply` (with or without `--site-dir`)
  keep them and refuse `cp-*` files in the owner's `--site-dir`; the owner's own files are never touched by a set.

### Allowlist changes from the control plane (v0.26.0, OFF by default)

Why: a probe outside the allowlist makes the agent refuse its whole list, and only root could widen the allowlist
(answers.yaml / template). Why bounded: the allowlist is the host owner's guard against a compromised control plane,
so changing it from that control plane is off by default and limited by ceilings the host owner sets.

- **Host switch + ceilings** (answers.yaml, root only, like `agent.update` / `agent.site`; missing = off):

  ```yaml
  agent:
    allow_edit:
      allow: true        # the control plane may add to this host's allowlist
      ping: false        # it may switch ping on (the prober unit gets CAP_NET_RAW)
      max_probes: 50     # ceiling for its max_probes (0 = the value without the overlay; never above 100)
  ```

  The inventory reports `allow_edit {allow, ping, max_probes}`; its `allow` is the EFFECTIVE list (with the overlay).
- **Flow:** the signed document carries `allow {revision, allow {domains, networks, ports, max_probes, min_interval_s,
  ping}}` = the control plane's COMPLETE overlay (all empty = remove it), never together with a new update or
  overlay set (one root job per document; those go first). The agent checks the switch and the bounds and hands a
  new revision to root (same request file and unit). Root: the request again (`self-update.json` also keeps
  `allow_revision`), the switch and ceilings re-read from answers.yaml, the bounds again, the lock, the record; then
  it writes `config/agent-allow.cp.yaml` (root 644, the template's format; empty overlay = file removed) and runs
  `monitoring-agent update --no-fetch` (re-renders the prober unit, smoke run, automatic rollback; on failure the
  previous overlay file is put back). Result in `agent/allow-result.json` (ok | failed | rolled_back | refused),
  reported once as status `allow`. answers.yaml is never edited: the overlay cannot touch url, key, update or site.
- **Bounds** (agent and root): domains by the domain pattern, networks a CIDR no wider than /16 (IPv4, also as
  IPv4-mapped IPv6) or /48 (IPv6), never a default route; at most 64 domains / networks / ports; ports 1-65535;
  max_probes 0 or up to the ceiling; min_interval_s 0 or at least 15; ping only with `allow_edit.ping`.
- **Effective list** (agent, plan / apply / update) = template + answers.yaml extras + overlay: lists joined, a
  non-zero number of the overlay replaces (max_probes clamped to the ceiling), ping when either allows it (the
  overlay's only with `allow_edit.ping`). With the switch off an installed overlay is ignored. The overlay counts
  only after root applied it: the probes of the same document are checked against the installed allowlist.

### Disk scan (v0.29.0)

Why: a console can see that a disk is 97 % full, but finding WHAT fills it meant logging in and running `du` /
ncdu. The agent itself cannot do it: it has no capabilities and `ProtectHome=yes`, so most of /var/lib, Oracle's
trees, /home and /root are unreadable to it.

- **Host switch** (answers.yaml, root only; missing = off):

  ```yaml
  agent:
    disk_scan:
      allow: true
      exclude: [/home/alice]   # absolute paths never walked (their size is not listed)
  ```

  With the switch on, apply installs the oneshot unit `monitoring-diskscan` (linked, never enabled) and the polkit
  rule lets the agent START it (nothing else). The inventory reports `disk_scan`.
- **The scanner** (`monitoring-agent disk-scan`, `internal/diskscan`): user monitoring-agent with ONLY
  `CAP_DAC_READ_SEARCH` (list any folder, stat any entry), `NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectHome=read-only`, `PrivateNetwork=yes`, writes only `<prefix>/agent`, Nice 19, idle IO, 50 % CPU, 200 MB,
  10 min (then the result is marked partial). It never opens a regular file and never follows a symlink. Per local
  filesystem (ext*, xfs, btrfs, zfs, vfat ...; one entry per device; fullest first, at most 16), like `du -x`:
  allocated sizes, hard links once; a folder tree 4 levels deep (top 10 children per folder, only >= 0.5 % of the
  used space) and the 20 biggest files >= 100 MiB (path, size, mtime). Result `agent/diskscan/result.json` <= 256 KB
  (deeper levels pruned first).
- **When** (the agent, every poll): never scanned or the last start >= 24 h ago (daily); a disk >= 85 % full and the
  last start >= 6 h ago (full); or the signed document carries `disk_scan {id}` (request; not a root job, may come
  with anything; answered as status `disk_scan {id, result: started | busy | refused | failed}`). The agent writes
  `agent/diskscan/trigger.json {id, reason, at}` and starts the unit; the result names the trigger it answers
  (`trigger_at`), so a running scan is "busy" for up to 11 min.
- **Upload**: a result newer than the last one sent goes to `POST <url>v1/diskscan` (signed like the others); a 4xx
  (an older control plane) is not retried. Paths may be personal: the control plane shows them to trusted roles only.

### Service re-scan (v0.32.0)

Why: the service scan (`internal/detect`) ran only in `plan` / `apply` / `update`, so a service installed later
(a new Tomcat, a database) stayed invisible in the console's inventory until someone ran an update by hand.

- **Host switch** (answers.yaml, root only; missing = off; read strictly: only `allow`, a bool):

  ```yaml
  agent:
    rescan:
      allow: true
  ```

  With the switch on, apply installs the oneshot unit `monitoring-scan` (linked, never enabled) and the polkit rule
  lets the agent START it (nothing else). The inventory reports `rescan_allowed`.
- **The scanner** (`monitoring-agent scan`): the same code path as `update` builds inventory.json with (live
  detection, the saved answers, the installed allowlist template + the agent's last probe list, `generate.Generate`),
  but it writes ONLY `<prefix>/inventory.json`: atomically (temp file in the prefix + rename), mode 644, owner root,
  and only when the bytes differ (the file has no volatile fields); an unchanged scan keeps the content and only sets
  the file's mtime to the scan time (`services_at` = the last COMPLETED scan: a console "scan now" is done when
  `services_at` advances, also when nothing changed). No
  configuration, unit or answers change, nothing is restarted. It takes the install lock (`.monitoring.lock`): while
  an apply / update runs it skips (they write inventory.json themselves).
- **Unit hardening**: root uid (the file and the prefix are root's) but `CapabilityBoundingSet=CAP_DAC_READ_SEARCH
  CAP_SYS_PTRACE` only, no `CAP_DAC_OVERRIDE` / `CAP_CHOWN` / `CAP_SYS_ADMIN`. What the detection reads and why:
  `CAP_DAC_READ_SEARCH` lists other users' `/proc/<pid>/fd` and the Oracle / Tomcat folders (alert log, logs,
  webapps) and reads the agent state; `CAP_SYS_PTRACE` is what the kernel asks for to read another user's
  `/proc/<pid>/fd/*` links (socket -> process -> port) and `/proc/<pid>/environ` (ORACLE_HOME, CATALINA_BASE ...).
  ptrace itself and `process_vm_readv/writev` are blocked by `SystemCallFilter`. No network (`IPAddressDeny=any`,
  `AF_UNIX` only); not `PrivateNetwork`: `/proc/net/tcp` must stay the host's. `ProtectSystem=strict`, the prefix
  writable except `bin`, `config`, `systemd`, `agent`, `data`, `backup` (read-only) and `secrets` (inaccessible),
  `ProtectHome=read-only`, Nice 19, idle IO, 50 % CPU, 200 MB, 4 min.
- **When** (the agent, every poll): the first poll after the agent started, then every 15 min after the last start;
  or the signed document carries `rescan {id}` (request; not a root job, may come with anything; answered as status
  `rescan {id, result: started | busy | refused | failed}`, once per id). A started scan counts as running for 5 min
  ("busy"). A start that fails (e.g. the unit not linked yet) is saved as `rescan_failed`, never counted as running,
  and tried again after 15 min.
- **Result**: nothing is uploaded separately. The agent re-reads inventory.json every poll and sends the inventory
  only on a change; it carries `services_at` (unix seconds, the mtime of inventory.json = the last completed scan:
  apply / update, or `monitoring-agent scan` with or without a change), so every scan sends one inventory.

### Switch a service on (v0.33.0, OFF by default)

Why: the scan finds services (inventory.json), but answers.yaml is root's: the console could show "Redis found, not
monitored" and nothing more. Like the allowlist overlay, the control plane may switch on a FOUND service whose
profile needs no login and no new secret, inside the host owner's switch, with the normal update path (validate,
smoke run, automatic rollback).

- **Host switch** (answers.yaml, root only; missing = off):

  ```yaml
  agent:
    services_edit:
      allow: true
  ```

  The inventory reports `services_edit` (the switch) and `services_cp {revision, set}` (the installed set; revision 0
  and `{}` = none).
- **Kinds**: a FIXED list in the code (`generate.CPServiceKinds`): `redis` and `nginx`. Anything else is refused.
  - **Redis**: the existing profile (`receiver_creator` rule, `REDIS_PORT`, `REDIS_PASSWORD` from the secrets); the
    set's port becomes `REDIS_PORT`. No password handling here: when Redis answers `NOAUTH` and the secrets have no
    `REDIS_PASSWORD`, root refuses with "Redis needs a password: put it in Secrets (REDIS_PASSWORD)" (a wrong
    password is not caught by this check).
  - **nginx** (new profile, contrib `nginx` receiver, beta): the `stub_status` page on `127.0.0.1:<port><status_path>`
    (`NGINX_MON`, `NGINX_PORT`, `NGINX_STATUS_PATH`; default path `/nginx_status`). Never on by default: only with
    answers `services.nginx.enabled: true` or the control plane's switch, and only when the scan found nginx.
    Before applying, root GETs the page (2 s, no redirects) and expects `Active connections:`; otherwise refused
    "nginx stub_status not answering at http://127.0.0.1:80/nginx_status: add the location (see the console steps)".
- **Merge rule** (generator, `generate.EffectiveServices`), answers win:
  - `services.<kind>.locked: true` = never by the control plane (a request switching it on is refused, an installed
    set is ignored for it);
  - `services.<kind>.enabled: true` = on anyway, with the answers' own port / path (the set changes nothing);
  - absent, or `enabled: false` WITHOUT `locked` = the control plane's `on: true` switches it on with its port (and
    path). `enabled: false` alone is today's "not decided yet" state on many hosts, so it does not lock a kind.
  - `on: false` = the control plane's switch is withdrawn (the answers decide again). The set is merged at generate
    time only: answers.yaml is never edited, and apply never saves the merged result into it.
- **Flow:** the signed document carries `services {revision, set {<kind>: {on, port, status_path}}}` = the control
  plane's COMPLETE set (empty = remove the file), never together with a new update, overlay set or allowlist overlay
  (one root job per document; those go first). The agent checks the switch, the kinds, the bounds (port 1-65535;
  `status_path` nginx only, `^/[A-Za-z0-9_./-]{1,64}$`) and `locked`, and hands a new revision to root (same request
  file and unit). Root: the request again (`self-update.json` also keeps `services_revision`), the switch and the
  answers re-read, the bounds again, the service check for each kind this set switches on, the lock, the record; then
  it writes `config/services.cp.yaml` (root 644; empty set = file removed) and runs `monitoring-agent update
  --no-fetch` (smoke run, automatic rollback; on failure the previous file is put back). Result in
  `agent/services-result.json` (applied | failed | rolled_back | refused), reported once as status `services`.

### Docker containers (v0.34.0, OFF by default)

Why: a Docker host can run many compose projects (one copy of an app per customer). Without the engine's API nobody
sees which copy is down, unhealthy, restarting or using the memory. The usual agents read the Docker socket, which is
root on the host: the collector user never gets the socket or the `docker` group. This feature needs neither.

- **Host switch** (answers.yaml, root only; missing = off; read strictly: only `allow`, a bool):

  ```yaml
  agent:
    docker:
      allow: true
  ```

  With the switch on, host.env gets `DOCKER_MON=on` and the inventory reports `docker_allowed: true`.
- **Names and states** (root, read-only, the existing service scan: `plan` / `apply` / `update` and the 15-min
  `monitoring-agent scan`): reads `/var/lib/docker/containers/<id>/config.v2.json` (no socket, no `docker` command)
  and writes the `docker` section of `inventory.json`: `{"at": <unix>, "containers": [ {id, name, image, project,
  service, working_dir, state, exit_code, health, restarts, started_at, finished_at} ]}`. Only these fields are
  copied: the name (without the leading `/`), `Config.Image`, the three labels `com.docker.compose.project`,
  `.service`, `.project.working_dir` (empty for a container started by hand), `State` (running, paused, restarting,
  dead, exit code, health status, started / finished time) and `RestartCount`. Never the environment, the command
  line, the mounts or any other label. `state` is `running | exited | restarting | paused | created | dead` (Docker's
  own order of checks); `finished_at` is 0 while a container runs. Sorted by name, at most 300 containers, strings
  trimmed and cut to 200 bytes. A host without `/var/lib/docker/containers` (or one the scan cannot read) gets no
  `docker` section and no error. `at` is the scan time, so with the switch on the file changes with every scan
  (an inventory-only change restarts nothing); `inventory.json` may be up to 256 KB (was 48 KB).
  The scan unit needs no change: it already reads other users' folders with `CAP_DAC_READ_SEARCH`.
- **Numbers** (no root, inside the running agent): every 60 s the agent reads the world-readable cgroup v2 files of
  each container, `/sys/fs/cgroup/system.slice/docker-<id>.scope/{cpu.stat,memory.current,memory.max}` (the systemd
  cgroup driver; with the cgroupfs driver `/sys/fs/cgroup/docker/<id>/` for the ids of the scan), for the containers of
  the newest `inventory.json` and any other `docker-*.scope` present, and serves them as Prometheus text on
  `127.0.0.1:9479/metrics` (loopback only):
  - `docker_container_cpu_seconds_total` (counter, `usage_usec` / 1e6),
  - `docker_container_memory_bytes` (gauge, `memory.current`),
  - `docker_container_memory_limit_bytes` (gauge, `memory.max`; no series when it says `max`),
  - labels `container_id` (first 12 hex), `container_name`, `compose_project`, `compose_service` (from the newest
    scan; a container not in it yet: name = the 12-hex id, project and service empty).
  Without cgroup v2 (`/sys/fs/cgroup/cgroup.controllers` missing) it exports nothing and logs that once. The agent
  unit needs no change: `ProtectSystem=strict` and `ProtectControlGroups=yes` leave `/sys/fs/cgroup` and the
  inventory file readable, and `AF_INET` is allowed for the loopback listener.
- **Collector**: the base config has a `receiver_creator/metrics` rule `prometheus/docker` for the host port 9479,
  active only with `DOCKER_MON=on`; it scrapes `127.0.0.1:9479` every 60 s into the normal metrics pipeline.
- **Inventory report**: top level `docker_allowed` (the switch); the file's `docker` section arrives inside
  `inventory` like the services. Send nothing to hosts that do not report `docker_allowed: true`.

### Agent settings from the console (v0.35.0, OFF by default)

Why: every `agent.<key>.allow` switch above is root's (answers.yaml) and off by default, so after an install somebody
had to log in and edit the answers for each one. The host owner now writes ONCE which of them the console may switch;
the console then turns them on and off through the same signed, root-checked path as the service switches.

- **Consent** (answers.yaml, root only; missing or empty = the console sets nothing):

  ```yaml
  agent:
    settings:
      allow: [disk_scan, rescan, docker, services_edit, allow_edit]
  ```

  Keys: a FIXED list in the code (`generate.SettingKeys`): `allow_edit`, `disk_scan`, `docker`, `rescan`,
  `services_edit`; each is the switch `agent.<key>.allow`. An unknown key in the list is an answers error. `install
  --console` writes the list from `--settings-allow disk_scan,rescan,...` (`none` = empty) or, without the flag, from
  the bootstrap bundle's `agent.settings_allow`.
- **Pinned**: a key whose `agent.<key>.allow` answers.yaml writes itself (any value, also `false`) is the host
  owner's: the console can never set it. A pin to `false` survives the rewrite of answers.yaml by apply (written back
  as `allow: false`).
- **Effective value** (one place, `generate.EffectiveAgent`, used by plan / apply / update, `scan`, `disk-scan`, the
  agent and root's jobs): pinned = the answers' value; else the key in the consent list AND in the installed set = the
  set's value; else off. answers.yaml is never edited, apply saves it as the owner wrote it.
- **Flow:** the signed document carries `settings {revision, set {<key>: bool}}` = the console's COMPLETE set (a key
  missing = not managed by the console; empty = remove the file), never together with a new update, overlay set,
  allowlist overlay or service switches (one root job per document; those go first). The agent checks the consent,
  the keys and the pins and hands a new revision to root (same request file and unit). Root re-verifies the request
  (`self-update.json` keeps `settings_revision`), re-reads the answers and refuses the WHOLE set (result `refused`,
  the detail names the key and why) when a key is unknown, not in the consent list or pinned. Otherwise it writes
  `config/settings.cp.yaml` (root 644) and runs `monitoring-agent update --no-fetch` (smoke run, automatic rollback;
  on failure the previous file is put back). Result in `agent/settings-result.json` (applied | failed | rolled_back |
  refused), reported once as status `settings`.
- **What a switch does** = what the same answers change does, through that `update`: `disk_scan` / `rescan` link or
  unlink the units `monitoring-diskscan` / `monitoring-scan` and their polkit entries; `docker` sets `DOCKER_MON` and
  the inventory's `docker` section (no group, no socket), the agent starts / stops its cgroup reader on its next poll;
  `services_edit` / `allow_edit` only open the matching console jobs (their files are read only while the switch is
  on). The agent re-reads the answers and the set every poll.
- **Inventory**: `settings_edit` (the consent list, sorted; absent = no consent), `settings_pinned` (always; `[]` =
  none), `settings_cp {revision, set}` (the installed set; revision 0 and `{}` = none; only with `settings_edit`). The
  switches it already reports (`disk_scan`, `rescan_allowed`, `services_edit`, `docker_allowed`, `allow_edit.allow`)
  are the effective values. Send a `settings` field only to agents that report `settings_edit` (v0.35.0+: an older
  agent rejects the unknown field).
