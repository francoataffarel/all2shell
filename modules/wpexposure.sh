#!/usr/bin/env bash
# description: Non-intrusive wp2shell exposure check (CVE-2026-63030/CVE-2026-60137)
set -Eeuo pipefail

# wpexposure is READ-ONLY. It fingerprints the WordPress version and checks whether the
# anonymous REST index advertises the /batch/v1 route. It never sends a batch request, a
# nested sub-request, or an SQL-injection payload — it confirms exposure, it does not exploit.

usage() {
  cat <<'EOF'
wpexposure — non-intrusive wp2shell exposure check

Usage: all2shell run wpexposure --target URL [--format text|json] [--timeout N] --yes-authorized

Fingerprints the WordPress version and checks whether the REST /batch/v1 route is
advertised to anonymous users. Read-only: no batch request, no SQLi probe, no payload.
Use it to confirm exposure and to verify a fix.

Full pre-auth RCE affects 6.9.0-6.9.4 and 7.0.0-7.0.1 (fixed in 6.9.5 / 7.0.2).

Exit codes: 0 not exposed / inconclusive · 10 exposed · 2 usage · 127 missing dependency
EOF
}

target=""; format="text"; timeout=15; authorized=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) [[ $# -gt 1 ]] || { echo 'wpexposure: missing value for --target' >&2; exit 2; }; target="$2"; shift 2 ;;
    --format) [[ $# -gt 1 ]] || { echo 'wpexposure: missing value for --format' >&2; exit 2; }; format="$2"; shift 2 ;;
    --timeout) [[ $# -gt 1 ]] || { echo 'wpexposure: missing value for --timeout' >&2; exit 2; }; timeout="$2"; shift 2 ;;
    --yes-authorized) authorized=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'wpexposure: unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[[ "$format" == text || "$format" == json ]] || { echo 'wpexposure: format must be text or json' >&2; exit 2; }
[[ "$target" =~ ^https?:// ]] || { echo 'wpexposure: provide an http(s) URL via --target' >&2; exit 2; }
[[ "$timeout" =~ ^[1-9][0-9]*$ ]] || { echo 'wpexposure: --timeout must be a positive integer' >&2; exit 2; }
[[ "$authorized" -eq 1 ]] || { echo 'wpexposure: pass --yes-authorized to confirm you own or may test this target' >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo 'wpexposure: curl is required' >&2; exit 127; }
if [[ "$format" == json ]]; then
  command -v jq >/dev/null 2>&1 || { echo 'wpexposure: jq is required for --format json' >&2; exit 127; }
fi

base="${target%/}"

# Plain GET helper. No --fail so we still read 4xx bodies; never sends a payload.
fetch() { curl --location --max-time "$timeout" --silent --show-error "$@" 2>/dev/null || true; }

# Semantic version comparison via sort -V.
ver_le() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]; }
ver_ge() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" == "$1" ]]; }
in_full_rce_range() {
  local v="$1"
  { ver_ge "$v" 6.9.0 && ver_le "$v" 6.9.4; } && return 0
  { ver_ge "$v" 7.0.0 && ver_le "$v" 7.0.1; } && return 0
  return 1
}
in_sqli_range() { local v="$1"; ver_ge "$v" 6.8.0 && ver_le "$v" 6.8.5; }

home_html="$(fetch "$base/")"
feed_xml="$(fetch "$base/feed/")"
rest_index="$(fetch -H 'Accept: application/json' "$base/wp-json/")"

version="unknown"
if [[ "$home_html" =~ content=\"WordPress\ ([0-9]+\.[0-9]+(\.[0-9]+)?)\" ]]; then
  version="${BASH_REMATCH[1]}"
elif [[ "$feed_xml" =~ wordpress\.org/\?v=([0-9]+\.[0-9]+(\.[0-9]+)?) ]]; then
  version="${BASH_REMATCH[1]}"
fi

batch_route="absent"
if printf '%s' "$rest_index" | grep -q 'batch/v1'; then
  batch_route="advertised"
fi

verdict="inconclusive"
reason="could not determine WordPress version"
if [[ "$version" != unknown ]]; then
  if in_full_rce_range "$version"; then
    verdict="exposed"; reason="version $version is in a full pre-auth RCE range"
  elif in_sqli_range "$version"; then
    verdict="exposed"; reason="version $version is in the SQL-injection range (update to 6.8.6+)"
  else
    verdict="not-affected-version"; reason="version $version is outside the affected ranges"
  fi
fi

if [[ "$format" == json ]]; then
  jq -n \
    --arg target "$base" \
    --arg version "$version" \
    --arg batch_route "$batch_route" \
    --arg verdict "$verdict" \
    --arg reason "$reason" \
    '{target:$target, intrusive:false, wordpress_version:$version, rest_batch_route:$batch_route, verdict:$verdict, reason:$reason}'
else
  printf 'wp2shell exposure: %s\n' "$base"
  printf '  WordPress version: %s\n' "$version"
  printf '  REST batch route:  %s\n' "$batch_route"
  printf '  Verdict:           %s (%s)\n' "$verdict" "$reason"
  if [[ "$verdict" == exposed ]]; then
    printf '  Remediation:       update to 7.0.2 / 6.9.5, or require auth on /batch/v1 (see vuln-packs/wp2shell)\n'
  fi
fi

[[ "$verdict" == exposed ]] && exit 10
exit 0
