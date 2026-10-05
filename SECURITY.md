# Security policy

auto-mon-collector runs as root and installs software, so security reports are welcome and handled first.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository.

Include what you found, how to reproduce it and the affected version (`amc version`). You will get an answer
as soon as possible; a fix and a release note follow once the issue is understood.

## Supported versions

Only the latest release is supported while the project is in early development.

## Scope

In scope: the installer (`amc`), `get.sh`, release artifacts and their signatures, generated configuration
that weakens a host (permissions, secrets handling). Out of scope: vulnerabilities in the OpenTelemetry
Collector itself (report those upstream) and in the monitored services.
