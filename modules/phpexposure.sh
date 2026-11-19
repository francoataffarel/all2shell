#!/usr/bin/env bash
# description: Non-intrusive PHP2Shell exposure check (CVE-2026-109618/109619)
set -Eeuo pipefail

# phpexposure is READ-ONLY. It reads the PHP version per branch (php -v), whether
# session.upload_progress is enabled (php -i), and optionally the PHP version advertised in
# a remote server's headers. It sends no upload-progress payload and no exploit request.

usage() {
  cat <<'EOF'
phpexposure — non-intrusive PHP2Shell exposure check

Usage: all2shell run phpexposure [--target URL] [--format text|json] [--timeout N] --yes-authorized

Host-local checks:
  php -v    version per branch -> fixed at 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (<8.2 is EOL)
  php -i    session.upload_progress.enabled -> relevant to the partial stopgap

Optional remote check (--target): fingerprint the PHP version from Server / X-Powered-By.

Exit codes: 0 ok · 10 exposed · 2 usage · 127 missing dependency.
EOF
}

target=""; format="text"; timeout=15; authorized=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) [[ $# -gt 1 ]] || { echo 'phpexposure: missing value for --target' >&2; exit 2; }; target="$2"; shift 2 ;;
    --format) [[ $# -gt 1 ]] || { echo 'phpexposure: missing value for --format' >&2; exit 2; }; format="$2"; shift 2 ;;
    --timeout) [[ $# -gt 1 ]] || { echo 'phpexposure: missing value for --timeout' >&2; exit 2; }; timeout="$2"; shift 2 ;;
    --yes-authorized) authorized=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'phpexposure: unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[[ "$format" == text || "$format" == json ]] || { echo 'phpexposure: format must be text or json' >&2; exit 2; }
[[ "$timeout" =~ ^[1-9][0-9]*$ ]] || { echo 'phpexposure: --timeout must be a positive integer' >&2; exit 2; }
[[ "$authorized" -eq 1 ]] || { echo 'phpexposure: pass --yes-authorized to confirm you own or may test this target' >&2; exit 2; }
[[ "$format" == json ]] && { command -v jq >/dev/null 2>&1 || { echo 'phpexposure: jq is required for --format json' >&2; exit 127; }; }

have_php=0; command -v php >/dev/null 2>&1 && have_php=1
[[ "$have_php" -eq 1 || -n "$target" ]] || {
  echo 'phpexposure: run on the PHP host (php binary needed) or pass --target URL for a header fingerprint' >&2
  exit 127
}

ver_le() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]; }
ver_ge() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" == "$1" ]]; }

fixed_for_branch() {
  case "$1" in
    8.5) echo 8.5.12 ;;
    8.4) echo 8.4.27 ;;
    8.3) echo 8.3.36 ;;
    8.2) echo 8.2.35 ;;
    *)   echo "" ;;
  esac
}

version="unknown"; source_of_version="none"; upload_progress="unknown"

if [[ "$have_php" -eq 1 ]]; then
  pline="$(php -v 2>/dev/null | head -n1 || true)"
  [[ "$pline" =~ PHP\ ([0-9]+\.[0-9]+\.[0-9]+) ]] && { version="${BASH_REMATCH[1]}"; source_of_version="php -v"; }
  upline="$(php -i 2>/dev/null | grep -iE 'session\.upload_progress\.enabled' | head -n1 || true)"
  if [[ "$upline" == *"=> On"* || "$upline" == *"=> 1"* ]]; then upload_progress="enabled"
  elif [[ "$upline" == *"=> Off"* || "$upline" == *"=> 0"* ]]; then upload_progress="disabled"; fi
fi

if [[ "$version" == unknown && -n "$target" ]] && command -v curl >/dev/null 2>&1; then
  hdrs="$(curl --silent --show-error --head --location --max-time "$timeout" "$target" 2>/dev/null || true)"
  if [[ "$hdrs" =~ PHP/([0-9]+\.[0-9]+\.[0-9]+) ]]; then version="${BASH_REMATCH[1]}"; source_of_version="response header"; fi
fi

verdict="inconclusive"; reason="could not determine the PHP version (expose_php may be Off)"
if [[ "$version" != unknown ]]; then
  branch="${version%.*}"
  fixed="$(fixed_for_branch "$branch")"
  if [[ -n "$fixed" ]]; then
    if ver_ge "$version" "$fixed"; then
      verdict="not-affected"; reason="version $version is at or above the $branch fix ($fixed)"
    else
      verdict="exposed"; reason="version $version is below the $branch fix ($fixed)"
    fi
  elif ver_le "$version" 8.1.999; then
    verdict="exposed"; reason="version $version is on an end-of-life branch (<8.2); no upstream fix — upgrade"
  else
    verdict="review"; reason="version $version is outside the known affected branches; confirm against the advisory"
  fi
fi

if [[ "$format" == json ]]; then
  jq -n \
    --arg version "$version" --arg src "$source_of_version" --arg upload "$upload_progress" \
    --arg verdict "$verdict" --arg reason "$reason" \
    '{intrusive:false, php_version:$version, version_source:$src, session_upload_progress:$upload,
      verdict:$verdict, reason:$reason}'
else
  printf 'PHP2Shell exposure\n'
  printf '  PHP version:            %s (%s)\n' "$version" "$source_of_version"
  printf '  session.upload_progress: %s\n' "$upload_progress"
  printf '  Verdict:                %s (%s)\n' "$verdict" "$reason"
  if [[ "$verdict" == exposed ]]; then
    printf '  Remediation:            update to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (see vuln-packs/php2shell)\n'
    [[ "$upload_progress" == enabled ]] && printf '  Stopgap:                session.upload_progress.enabled=0 (partial)\n'
  fi
fi

[[ "$verdict" == exposed ]] && exit 10
exit 0
