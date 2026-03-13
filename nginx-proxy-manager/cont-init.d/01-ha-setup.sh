#!/usr/bin/with-contenv bash
# Runs early in s6's cont-init sequence.
# Creates the /data sub-directories NPM expects on the HA persistent volume.

mkdir -p /data/letsencrypt /data/nginx /data/logs /data/access
