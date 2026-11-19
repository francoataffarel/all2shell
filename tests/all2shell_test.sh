#!/usr/bin/env bash
set -Eeuo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
pass=0
assert_contains() { [[ "$1" == *"$2"* ]] || { printf 'FAIL: expected %q in output\n' "$2" >&2; exit 1; }; pass=$((pass + 1)); }

# Runs "$root/all2shell" with the given args, asserts the exit status and an output substring.
assert_run() { # <expected_status> <needle> <args...>
  local expected="$1" needle="$2"; shift 2
  local out status
  set +e; out="$("$root/all2shell" "$@" 2>&1)"; status=$?; set -e
  [[ "$status" -eq "$expected" ]] || { printf 'FAIL: %q expected status %s got %s\n' "$*" "$expected" "$status" >&2; exit 1; }
  assert_contains "$out" "$needle"
}

# --- core runner -----------------------------------------------------------------------
assert_contains "$("$root/all2shell" version)" 'all2shell 0.1.0'
assert_contains "$("$root/all2shell" list)" 'wp2shell'
assert_contains "$("$root/all2shell" help wp2shell)" 'read-only checks'
assert_run 1 'unknown command' not-a-command
assert_run 1 'invalid module name' run ../etc/passwd

# wp2shell authorization guard
assert_run 2 'confirm you own or may audit' run wp2shell --path .

# --- exposure modules are discovered ---------------------------------------------------
for m in wpexposure nginxexposure javaexposure phpexposure; do
  assert_contains "$("$root/all2shell" list)" "$m"
done

# --- exposure modules: authorization gate + usage (all network/binary free) ------------
assert_run 2 'yes-authorized' run wpexposure --target https://example.com
assert_run 2 'yes-authorized' run nginxexposure
assert_run 2 'yes-authorized' run javaexposure
assert_run 2 'yes-authorized' run phpexposure
assert_run 0 'Usage' run wpexposure --help
assert_run 2 'format must be text or json' run wpexposure --target https://example.com --format xml --yes-authorized

# --- advisory packs --------------------------------------------------------------------
for p in wp2shell nginx2root java4shell php2shell; do
  assert_contains "$("$root/all2shell" advisories)" "$p"
done
assert_contains "$("$root/all2shell" advisory nginx2root)" '1.31.9'
assert_run 1 'invalid advisory name' advisory ../etc
assert_run 1 'unknown advisory' advisory nope

printf 'PASS: %d assertions\n' "$pass"
