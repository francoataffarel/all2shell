#!/usr/bin/env bash
# description: Inspect headers and status for an HTTP endpoint
set -Eeuo pipefail
[[ "${1:-}" == --help ]] && { echo 'Usage: all2shell run httpcheck <https://url>'; exit 0; }
url="${1:-}"; [[ "$url" =~ ^https?:// ]] || { echo 'httpcheck: provide an http(s) URL' >&2; exit 2; }
command -v curl >/dev/null || { echo 'httpcheck: curl is required' >&2; exit 127; }
curl --fail-with-body --location --max-time 15 --silent --show-error --dump-header - --output /dev/null "$url"
