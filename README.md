# All2Shell ⚡

> One CLI to rule your shell workflows — composable, inspectable and safe by default.

[![CI](https://github.com/francoataffarel/all2shell/actions/workflows/ci.yml/badge.svg)](https://github.com/francoataffarel/all2shell/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-7c3aed.svg)](LICENSE)
[![Shell: Bash](https://img.shields.io/badge/shell-Bash-22c55e.svg)](https://www.gnu.org/software/bash/)

All2Shell is a tiny module runner for operators who are tired of remembering dozens
of disconnected commands. Every module is plain Bash, easy to review and easy to
extend. The first security module is **wp2shell**, a read-only WordPress auditor.

```console
$ ./all2shell list
MODULE           DESCRIPTION
httpcheck        Inspect headers and status for an HTTP endpoint
wp2shell         Audit and harden an authorized local WordPress installation

$ ./all2shell run wp2shell --path /var/www/html --yes-authorized
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
- Additional defensive modules for Java, Nginx and containers
- Structured run logs and policy-as-code

MIT licensed. Built for operators who value speed **and** clarity.
