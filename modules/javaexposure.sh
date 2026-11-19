#!/usr/bin/env bash
# description: Non-intrusive Java4Shell exposure check (CVE-2026-114938)
set -Eeuo pipefail

# javaexposure is READ-ONLY and host-local. It reads the JDK version (java -version) and the
# CPU flags (/proc/cpuinfo) to decide whether an affected runtime is running on AVX-512 VBMI
# hardware. It sends no network traffic and no decoder input — it establishes exposure only.

usage() {
  cat <<'EOF'
javaexposure — non-intrusive Java4Shell exposure check

Usage: all2shell run javaexposure [--format text|json] --yes-authorized

Host-local checks:
  java -version      runtime + version   -> affected: 17.0.6-17.0.21.0.3, 21<=21.0.13.0.3,
                                            25<=25.0.5.0.3, 27<=27.0.1.0.3 (8/11 not affected)
  /proc/cpuinfo      avx512f avx512bw avx512vbmi bmi2  -> all four present = affected hardware

A host is exposed only when an affected runtime runs on AVX-512 VBMI hardware. Fixed builds:
17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1. Exit codes: 0 ok · 10 exposed · 2 usage · 127 dep.
EOF
}

format="text"; authorized=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --format) [[ $# -gt 1 ]] || { echo 'javaexposure: missing value for --format' >&2; exit 2; }; format="$2"; shift 2 ;;
    --yes-authorized) authorized=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'javaexposure: unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[[ "$format" == text || "$format" == json ]] || { echo 'javaexposure: format must be text or json' >&2; exit 2; }
[[ "$authorized" -eq 1 ]] || { echo 'javaexposure: pass --yes-authorized to confirm you own or may test this host' >&2; exit 2; }
[[ "$format" == json ]] && { command -v jq >/dev/null 2>&1 || { echo 'javaexposure: jq is required for --format json' >&2; exit 127; }; }
command -v java >/dev/null 2>&1 || { echo 'javaexposure: java is required (run on the Java host)' >&2; exit 127; }

ver_ge() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" == "$1" ]]; }
ver_lt() { ! ver_ge "$1" "$2"; }   # strict less-than

# --- Runtime version -------------------------------------------------------------------
# Parse the whole output, not just line 1: JAVA_TOOL_OPTIONS prints a "Picked up ..." banner first.
jout="$(java -version 2>&1 || true)"
jver="unknown"
[[ "$jout" =~ \"([0-9][0-9._]+)\" ]] && jver="${BASH_REMATCH[1]}"

# Normalise Java 8 "1.8.0_x" to major 8; otherwise take the leading number.
major="unknown"
case "$jver" in
  1.8.*|1.8) major=8 ;;
  unknown)   major=unknown ;;
  *)         major="${jver%%.*}" ;;
esac
# Comparable short version (strip Java 8 underscore builds to 1.8).
short="${jver%%_*}"

# Compare the full build against the precise fixed release for each branch (e.g. 21.0.13.0.3
# is below the fix 21.0.13.1, so it is affected). Java 8/11 and 17.0.0-17.0.5 lack the code.
runtime_state="unknown"   # affected | fixed | not-affected | unknown
case "$major" in
  8|11)
    runtime_state="not-affected" ;;
  17)
    if ver_lt "$short" 17.0.6; then runtime_state="not-affected"
    elif ver_lt "$short" 17.0.21.1; then runtime_state="affected"
    else runtime_state="fixed"; fi ;;
  21)
    if ver_lt "$short" 21.0.13.1; then runtime_state="affected"; else runtime_state="fixed"; fi ;;
  25)
    if ver_lt "$short" 25.0.5.1; then runtime_state="affected"; else runtime_state="fixed"; fi ;;
  27)
    if ver_lt "$short" 27.0.1.1; then runtime_state="affected"; else runtime_state="fixed"; fi ;;
  *)
    runtime_state="unknown" ;;
esac

# --- Hardware gate ---------------------------------------------------------------------
hardware="unknown"   # affected | not-affected | unknown
if [[ -r /proc/cpuinfo ]]; then
  flags="$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null || true)"
  if [[ -n "$flags" ]]; then
    hardware="affected"
    for f in avx512f avx512bw avx512vbmi bmi2; do
      printf '%s' "$flags" | tr ' ' '\n' | grep -qx "$f" || { hardware="not-affected"; break; }
    done
  fi
fi

# --- Verdict ---------------------------------------------------------------------------
verdict="review"; reason="could not fully determine runtime or CPU"
if [[ "$hardware" == "not-affected" ]]; then
  verdict="not-affected"; reason="CPU lacks an AVX-512 VBMI flag; the vulnerable decoder cannot run"
elif [[ "$runtime_state" == "not-affected" || "$runtime_state" == "fixed" ]]; then
  verdict="not-affected"; reason="runtime $jver is at or above the fixed build for its branch"
elif [[ "$hardware" == "affected" && "$runtime_state" == "affected" ]]; then
  verdict="exposed"; reason="runtime $jver (below the fixed .1 build) on AVX-512 VBMI hardware; confirm decoder reachability for RCE vs crash"
elif [[ "$runtime_state" == "affected" ]]; then
  verdict="review"; reason="runtime $jver is affected but CPU flags are unreadable — check AVX-512 VBMI manually"
fi

if [[ "$format" == json ]]; then
  jq -n \
    --arg runtime "$jver" --arg major "$major" --arg runtime_state "$runtime_state" \
    --arg hardware "$hardware" --arg verdict "$verdict" --arg reason "$reason" \
    '{intrusive:false, java_runtime:$runtime, java_major:$major, runtime_state:$runtime_state,
      cpu_avx512vbmi:$hardware, verdict:$verdict, reason:$reason}'
else
  printf 'Java4Shell exposure\n'
  printf '  Java runtime:      %s (major %s)\n' "$jver" "$major"
  printf '  Runtime state:     %s\n' "$runtime_state"
  printf '  AVX-512 VBMI CPU:  %s\n' "$hardware"
  printf '  Verdict:           %s (%s)\n' "$verdict" "$reason"
  if [[ "$verdict" == exposed ]]; then
    printf '  Remediation:       update to a .1 build, or -XX:-UseBASE64Intrinsics (see vuln-packs/java4shell)\n'
  fi
fi

[[ "$verdict" == exposed ]] && exit 10
exit 0
