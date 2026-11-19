#!/usr/bin/env bash
# description: Non-intrusive nginx2root exposure check (CVE-2026-123007 et al.)
set -Eeuo pipefail

# nginxexposure is READ-ONLY. It reads the nginx version, the compiled-in HTTP/2 and
# HTTP/3 modules, the enabled directives, and (optionally) whether HTTP/2 is reachable
# over TLS. It never sends HTTP/2 control frames or any exploit payload — it establishes
# exposure, it does not exploit.

usage() {
  cat <<'EOF'
nginxexposure — non-intrusive nginx2root exposure check

Usage: all2shell run nginxexposure [--target HOST[:PORT]] [--format text|json] [--timeout N] --yes-authorized

Host-local checks (run on the nginx server):
  nginx -v        version                       -> CVE-2026-123007 range 1.9.5-1.31.8
  nginx -V        --with-http_v2_module / v3     -> is the vulnerable code compiled in
  nginx -T        enabled http2/http3/mail       -> which attack paths are live

Optional remote check (--target): a single TLS ALPN probe to see whether the server
negotiates HTTP/2 from outside. Needs openssl.

Complete fix: nginx 1.31.9 (mainline) / 1.30.7 (stable). Exit codes: 0 ok · 10 exposed ·
2 usage · 127 missing dependency.
EOF
}

target=""; format="text"; timeout=15; authorized=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) [[ $# -gt 1 ]] || { echo 'nginxexposure: missing value for --target' >&2; exit 2; }; target="$2"; shift 2 ;;
    --format) [[ $# -gt 1 ]] || { echo 'nginxexposure: missing value for --format' >&2; exit 2; }; format="$2"; shift 2 ;;
    --timeout) [[ $# -gt 1 ]] || { echo 'nginxexposure: missing value for --timeout' >&2; exit 2; }; timeout="$2"; shift 2 ;;
    --yes-authorized) authorized=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'nginxexposure: unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[[ "$format" == text || "$format" == json ]] || { echo 'nginxexposure: format must be text or json' >&2; exit 2; }
[[ "$timeout" =~ ^[1-9][0-9]*$ ]] || { echo 'nginxexposure: --timeout must be a positive integer' >&2; exit 2; }
[[ "$authorized" -eq 1 ]] || { echo 'nginxexposure: pass --yes-authorized to confirm you own or may test this host' >&2; exit 2; }
if [[ "$format" == json ]]; then
  command -v jq >/dev/null 2>&1 || { echo 'nginxexposure: jq is required for --format json' >&2; exit 127; }
fi

have_nginx=0; command -v nginx >/dev/null 2>&1 && have_nginx=1
[[ "$have_nginx" -eq 1 || -n "$target" ]] || {
  echo 'nginxexposure: run on the nginx host (nginx binary needed) or pass --target HOST for a remote ALPN probe' >&2
  exit 127
}

# Semantic version comparison via sort -V.
ver_le() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]; }
ver_ge() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" == "$1" ]]; }
is_fixed_123007() {
  local v="$1"
  ver_ge "$v" 1.31.9 && return 0                      # mainline fix and later
  { ver_ge "$v" 1.30.7 && ver_le "$v" 1.30.999; } && return 0   # stable 1.30 branch backport
  return 1
}
affected_123007() {
  local v="$1"
  [[ "$v" == unknown ]] && return 1
  ver_ge "$v" 1.9.5 && ver_le "$v" 1.31.8 && ! is_fixed_123007 "$v"
}

version="unknown"; http2_module="unknown"; http3_module="unknown"
http2_enabled="unknown"; http3_enabled="unknown"; mail_authhttp="unknown"; resolver_mirror="unknown"

if [[ "$have_nginx" -eq 1 ]]; then
  vline="$(nginx -v 2>&1 || true)"
  [[ "$vline" =~ nginx/([0-9]+\.[0-9]+\.[0-9]+) ]] && version="${BASH_REMATCH[1]}"

  vflags="$(nginx -V 2>&1 || true)"
  case "$vflags" in *--with-http_v2_module*) http2_module="present" ;; *) http2_module="absent" ;; esac
  case "$vflags" in *--with-http_v3_module*) http3_module="present" ;; *) http3_module="absent" ;; esac

  # nginx -T dumps the full config (needs privileges); strip comments before matching.
  conf="$(nginx -T 2>/dev/null || true)"
  if [[ -n "$conf" ]]; then
    stripped="$(printf '%s\n' "$conf" | sed 's/#.*//')"
    http2_enabled=no; http3_enabled=no; mail_authhttp=no; resolver_mirror=no
    printf '%s' "$stripped" | grep -Eq 'listen[[:space:]].*http2|[[:space:]]http2[[:space:]]+on[[:space:]]*;' && http2_enabled=yes
    printf '%s' "$stripped" | grep -Eq 'listen[[:space:]].*quic|[[:space:]]http3[[:space:]]+on[[:space:]]*;' && http3_enabled=yes
    printf '%s' "$stripped" | grep -Eq '[[:space:]]auth_http[[:space:]]' && mail_authhttp=yes
    { printf '%s' "$stripped" | grep -Eq '[[:space:]]resolver[[:space:]]' && printf '%s' "$stripped" | grep -Eq '[[:space:]]mirror[[:space:]]'; } && resolver_mirror=yes
  fi
fi

# Optional external ALPN probe: does the server negotiate HTTP/2 from outside?
http2_reachable="not-checked"
if [[ -n "$target" ]]; then
  host="${target%%:*}"; port="${target##*:}"; [[ "$port" == "$host" ]] && port=443
  if command -v openssl >/dev/null 2>&1; then
    alpn="$(openssl s_client -connect "$host:$port" -servername "$host" -alpn h2 </dev/null 2>/dev/null | grep -E 'ALPN protocol' || true)"
    if [[ "$alpn" == *"ALPN protocol: h2"* ]]; then http2_reachable="yes"
    elif [[ -n "$alpn" ]]; then http2_reachable="no"
    else http2_reachable="inconclusive"; fi
  else
    http2_reachable="openssl-missing"
  fi
  # If we have no local version, try the remote Server banner (often suppressed).
  if [[ "$version" == unknown ]] && command -v curl >/dev/null 2>&1; then
    banner="$(curl --silent --show-error --head --max-time "$timeout" "https://$host:$port/" 2>/dev/null | grep -i '^server:' || true)"
    [[ "$banner" =~ nginx/([0-9]+\.[0-9]+\.[0-9]+) ]] && version="${BASH_REMATCH[1]}"
  fi
fi

# Verdict for the headline path (CVE-2026-123007). HTTP/2 is "live" if enabled locally or
# reachable remotely; if we could not read either, treat module-present as the weaker signal.
http2_live="unknown"
[[ "$http2_enabled" == yes || "$http2_reachable" == yes ]] && http2_live="yes"
[[ "$http2_enabled" == no && ( "$http2_reachable" == no || "$http2_reachable" == "not-checked" ) ]] && http2_live="no"

verdict="inconclusive"; reason="could not establish version and HTTP/2 state"
if affected_123007 "$version"; then
  if [[ "$http2_live" == yes ]]; then
    verdict="exposed"; reason="version $version in range and HTTP/2 is live (CVE-2026-123007)"
  elif [[ "$http2_live" == no ]]; then
    verdict="vulnerable-code-present"; reason="version $version in range but HTTP/2 is not live; patch still required"
  else
    verdict="review"; reason="version $version in range; confirm HTTP/2 exposure"
  fi
elif [[ "$version" != unknown ]]; then
  verdict="not-affected-version"; reason="version $version is outside the CVE-2026-123007 range (confirm distro backport)"
fi

other_paths=""
[[ "$http3_enabled" == yes ]] && other_paths+="HTTP/3 enabled (CVE-2026-121810); "
[[ "$mail_authhttp" == yes ]] && other_paths+="mail auth_http (CVE-2026-113425); "
[[ "$resolver_mirror" == yes ]] && other_paths+="resolver+mirror (CVE-2026-123634); "
[[ -z "$other_paths" ]] && other_paths="none detected"

if [[ "$format" == json ]]; then
  jq -n \
    --arg version "$version" --arg http2_module "$http2_module" --arg http3_module "$http3_module" \
    --arg http2_enabled "$http2_enabled" --arg http2_reachable "$http2_reachable" \
    --arg verdict "$verdict" --arg reason "$reason" --arg other_paths "$other_paths" \
    '{intrusive:false, nginx_version:$version, http2_module:$http2_module, http3_module:$http3_module,
      http2_enabled:$http2_enabled, http2_reachable:$http2_reachable, verdict:$verdict, reason:$reason,
      other_affected_paths:$other_paths}'
else
  printf 'nginx2root exposure\n'
  printf '  nginx version:     %s\n' "$version"
  printf '  HTTP/2 module:     %s\n' "$http2_module"
  printf '  HTTP/2 enabled:    %s\n' "$http2_enabled"
  printf '  HTTP/2 reachable:  %s\n' "$http2_reachable"
  printf '  HTTP/3 module:     %s\n' "$http3_module"
  printf '  Verdict:           %s (%s)\n' "$verdict" "$reason"
  printf '  Other paths:       %s\n' "$other_paths"
  if [[ "$verdict" == exposed || "$verdict" == vulnerable-code-present ]]; then
    printf '  Remediation:       update to 1.31.9 / 1.30.7, or disable HTTP/2 (see vuln-packs/nginx2root)\n'
  fi
fi

[[ "$verdict" == exposed ]] && exit 10
exit 0
