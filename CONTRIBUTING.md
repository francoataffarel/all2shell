# Contributing

Keep modules small, deterministic and reviewable. A module must support `--help`,
validate all input, quote expansions, use timeouts for network calls and avoid
`eval`. Security modules must require explicit authorization and must not implement
credential theft, persistence, evasion, exploitation or remote-shell payloads.

Run `bash tests/all2shell_test.sh` and `shellcheck all2shell install.sh modules/*.sh tests/*.sh`
before opening a pull request.
