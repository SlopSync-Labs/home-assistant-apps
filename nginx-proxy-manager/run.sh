#!/usr/bin/env bash
# NOTE: This script is NOT copied into the container and is NOT the container
# entrypoint. NPM's image uses s6-overlay, and /init must run as PID 1.
#
# Startup logic lives in cont-init.d/01-ha-setup.sh, which s6 executes
# during its normal init sequence before NPM's services start.
#
# This file is kept as a placeholder per HA add-on repository convention.
echo "See cont-init.d/01-ha-setup.sh for container startup logic."
