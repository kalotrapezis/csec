#!/bin/sh
# Runs after the .deb/.rpm installs files. We only register the unit — the
# admin turns the filter on (and sets the proxy) with `sudo csec install`.
set -e
systemctl daemon-reload >/dev/null 2>&1 || true

echo "CSec installed. To activate the filter and set the proxy, run:"
echo "    sudo csec install"
