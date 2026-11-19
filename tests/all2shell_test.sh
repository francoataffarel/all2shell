#!/usr/bin/env bash
set -Eeuo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
pass=0
assert_contains() { [[ "$1" == *"$2"* ]] || { printf 'FAIL: expected %q in output\n' "$2" >&2; exit 1; }; pass=$((pass + 1)); }

assert_contains "$("$root/all2shell" version)" 'all2shell 0.1.0'
assert_contains "$("$root/all2shell" list)" 'wp2shell'
assert_contains "$("$root/all2shell" help wp2shell)" 'read-only checks'

set +e
output="$("$root/all2shell" run wp2shell --path . 2>&1)"; status=$?
set -e
[[ $status -eq 2 ]] || { echo 'FAIL: authorization guard did not return 2' >&2; exit 1; }
assert_contains "$output" 'confirm you own or may audit'
printf 'PASS: %d assertions\n' "$pass"
