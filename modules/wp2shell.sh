#!/usr/bin/env bash
# description: Audit and harden an authorized local WordPress installation
set -Eeuo pipefail

usage() {
  cat <<'EOF'
wp2shell — turn WordPress signals into safe shell actions

Usage: all2shell run wp2shell [--path PATH] [--format text|json] [--yes-authorized]

Performs read-only checks through WP-CLI: core integrity, update availability,
administrator inventory and risky file permissions. It does not exploit targets,
upload files, create users, or open a remote shell.
EOF
}

wp_path="."; format="text"; authorized=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --path) [[ $# -gt 1 ]] || { echo 'missing value for --path' >&2; exit 2; }; wp_path="$2"; shift 2 ;;
    --format) [[ $# -gt 1 ]] || { echo 'missing value for --format' >&2; exit 2; }; format="$2"; shift 2 ;;
    --yes-authorized) authorized=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'wp2shell: unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[[ "$format" == text || "$format" == json ]] || { echo 'wp2shell: format must be text or json' >&2; exit 2; }
[[ "$authorized" -eq 1 ]] || { echo 'wp2shell: pass --yes-authorized to confirm you own or may audit this installation' >&2; exit 2; }
command -v wp >/dev/null 2>&1 || { echo 'wp2shell: WP-CLI is required (https://wp-cli.org)' >&2; exit 127; }
[[ -d "$wp_path" ]] || { echo 'wp2shell: path is not a directory' >&2; exit 2; }
wp core is-installed --path="$wp_path" >/dev/null 2>&1 || { echo 'wp2shell: no WordPress installation found at path' >&2; exit 1; }

core_status="ok"
wp core verify-checksums --path="$wp_path" --quiet >/dev/null 2>&1 || core_status="warning"
core_updates="$(wp core check-update --path="$wp_path" --format=count 2>/dev/null || printf 'unknown')"
plugin_updates="$(wp plugin list --path="$wp_path" --update=available --format=count 2>/dev/null || printf 'unknown')"
admin_count="$(wp user list --path="$wp_path" --role=administrator --format=count 2>/dev/null || printf 'unknown')"
world_writable="$(find "$wp_path" -xdev -type f -perm -0002 2>/dev/null | wc -l | tr -d ' ')"

if [[ "$format" == json ]]; then
  printf '{"core_integrity":"%s","core_updates":"%s","plugin_updates":"%s","administrators":"%s","world_writable_files":"%s"}\n' \
    "$core_status" "$core_updates" "$plugin_updates" "$admin_count" "$world_writable"
else
  printf 'WordPress audit: %s\n' "$wp_path"
  printf '  Core integrity:       %s\n' "$core_status"
  printf '  Core updates:         %s\n' "$core_updates"
  printf '  Plugin updates:       %s\n' "$plugin_updates"
  printf '  Administrators:       %s\n' "$admin_count"
  printf '  World-writable files: %s\n' "$world_writable"
fi
