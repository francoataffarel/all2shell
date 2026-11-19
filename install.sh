#!/usr/bin/env bash
set -Eeuo pipefail
prefix="${PREFIX:-$HOME/.local}"
install -d "$prefix/bin" "$prefix/lib/all2shell/modules"
install -m 0755 all2shell "$prefix/lib/all2shell/all2shell"
install -m 0755 modules/*.sh "$prefix/lib/all2shell/modules/"
ln -sfn "$prefix/lib/all2shell/all2shell" "$prefix/bin/all2shell"
printf 'Installed all2shell to %s/bin/all2shell\n' "$prefix"
