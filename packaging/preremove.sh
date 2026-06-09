#!/bin/sh
# Runs before the package's files are removed.
#
# IMPORTANT: only undo the proxy on a real removal, NOT on an upgrade/reinstall.
#   rpm: $1 == 0       on final erase   (>0 == upgrade)
#   deb: $1 == remove  on removal       (upgrade == "upgrade")
# Otherwise upgrading the package would silently turn the filter off.
set -e

case "$1" in
    0|remove|purge)
        if [ -x /usr/bin/csec ]; then
            /usr/bin/csec _restore >/dev/null 2>&1 || true
        else
            systemctl disable --now csec.service >/dev/null 2>&1 || true
        fi
        ;;
    *)
        : # upgrade / reinstall — leave the running filter alone
        ;;
esac
