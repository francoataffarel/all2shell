# All2Shell ⚡

> One CLI to rule your shell workflows — composable, inspectable and safe by default.

[![CI](https://github.com/francoataffarel/all2shell/actions/workflows/ci.yml/badge.svg)](https://github.com/francoataffarel/all2shell/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-7c3aed.svg)](LICENSE)
[![Shell: Bash](https://img.shields.io/badge/shell-Bash-22c55e.svg)](https://www.gnu.org/software/bash/)

All2Shell is a tiny module runner for operators who are tired of remembering dozens
of disconnected commands. Every module is plain Bash, easy to review and easy to
extend. On top of the runner it ships **vulnerability advisory packs** — a blue-team
workflow to check exposure, apply mitigations and verify the fix for the 2026
"*Something2Shell*" RCE wave (wp2shell, nginx2root, Java4Shell, PHP2Shell).

```console
$ ./all2shell list
MODULE           DESCRIPTION
httpcheck        Inspect headers and status for an HTTP endpoint
wp2shell         Audit and harden an authorized local WordPress installation
wpexposure       Non-intrusive wp2shell exposure check (CVE-2026-63030/CVE-2026-60137)
nginxexposure    Non-intrusive nginx2root exposure check (CVE-2026-123007 et al.)
javaexposure     Non-intrusive Java4Shell exposure check (CVE-2026-114938)
phpexposure      Non-intrusive PHP2Shell exposure check (CVE-2026-109618/109619)

$ ./all2shell advisories
PACK         CVEs NAME
wp2shell     2    WordPress Core REST batch pre-authentication RCE
nginx2root   5    nginx remote code execution cluster (nginx2root)
java4shell   1    OpenJDK Base64 decoder memory corruption (Java4Shell)
php2shell    2    PHP core unauthenticated RCE pair (PHP2Shell)

$ ./all2shell run wpexposure --target https://example.com --yes-authorized
```

## Why it is different

- **Safe by default:** destructive or offensive behavior is out of scope.
- **Zero framework dependencies:** Bash is the runtime; modules declare their tools.
- **No magic:** each action is a short, reviewable script.
- **Automation friendly:** stable exit codes and JSON output where it matters.
- **Defense first:** explicit authorization gates for security-sensitive modules.

## Quick start

```bash
git clone https://github.com/francoataffarel/all2shell.git
cd all2shell
./all2shell doctor
./all2shell list
./all2shell help wp2shell
```

Install for the current user with `./install.sh`. Override the destination with
`PREFIX=/usr/local ./install.sh` when appropriate.

## Vulnerability advisory packs

Each pack under `vuln-packs/<id>/` is a self-contained, **defensive** workflow for one
CVE family: detect exposure, apply the right mitigation, verify the fix, then hunt. A pack
ships a machine-readable `advisory.yaml`, a runbook `README.md`, a non-intrusive Nuclei
template where a safe remote signal exists, and mitigation drop-ins where useful.

```console
$ ./all2shell advisories                        # list packs
$ ./all2shell advisory nginx2root               # show a pack's runbook
$ ./all2shell run phpexposure --yes-authorized  # run its exposure check
```

| Pack | CVEs | Exposure module |
|------|------|-----------------|
| `wp2shell` | CVE-2026-63030, CVE-2026-60137 | `wpexposure` — remote, read-only |
| `nginx2root` | CVE-2026-123007 (+4) | `nginxexposure` — local + ALPN probe |
| `java4shell` | CVE-2026-114938 | `javaexposure` — host-local |
| `php2shell` | CVE-2026-109618/109619 | `phpexposure` — local + header fingerprint |

The exposure checks are deliberately non-intrusive: they fingerprint versions and
configuration and never send an exploit payload. By design the packs do **not** contain
exploitation code — gaining access, dropping webshells or achieving RCE stays out of scope,
exactly as `wp2shell` and [`SECURITY.md`](SECURITY.md) state.

## Create a module

Add `modules/my-tool.sh`, include a `# description: ...` header and accept `--help`.
Modules receive their arguments unchanged and run in a new Bash process. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the contract and quality checklist.

## Responsible use

All2Shell is designed for systems you own or are explicitly authorized to operate.
`wp2shell` intentionally does not gain access, deploy webshells, create persistence,
or evade controls. See [`SECURITY.md`](SECURITY.md) for the threat model.

## Roadmap

- Signed third-party module registry
- Reproducible execution manifests
- More advisory packs as the "*Something2Shell*" wave continues
- `advisory --format json` for pipelines, and CI gating on exposure exit codes
- Structured run logs and policy-as-code

MIT licensed. Built for operators who value speed **and** clarity.
