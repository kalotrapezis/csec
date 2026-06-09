#!/bin/sh
# Runs after the package's files are removed.
set -e
systemctl daemon-reload >/dev/null 2>&1 || true
