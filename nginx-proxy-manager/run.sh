#!/usr/bin/env bash
set -euo pipefail

# Ensure persistent sub-directories exist on first run.
# NPM expects these under /data (mapped to the HA add-on data directory).
mkdir -p /data/letsencrypt /data/nginx /data/logs /data/access

# Hand off to NPM's own s6-overlay init process.
exec /init
