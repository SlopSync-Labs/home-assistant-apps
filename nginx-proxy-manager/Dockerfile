# Use the official Nginx Proxy Manager image directly.
# BUILD_FROM is declared to satisfy HA's build tooling but not used —
# we want the full NPM image, not the minimal HA base.
ARG BUILD_FROM
FROM jc21/nginx-proxy-manager:2.14.0

# Redirect Let's Encrypt certificate storage into the persistent /data volume
# so certs survive add-on restarts and updates.
RUN rm -rf /etc/letsencrypt \
    && ln -s /data/letsencrypt /etc/letsencrypt

# Run our HA setup script early in s6's cont-init sequence.
# This creates required /data sub-directories on the mounted volume before
# NPM's own services start.
COPY cont-init.d/01-ha-setup.sh /etc/cont-init.d/01-ha-setup.sh
RUN chmod +x /etc/cont-init.d/01-ha-setup.sh

EXPOSE 80 81 443

# Do NOT override ENTRYPOINT — s6-overlay (/init) must run as PID 1.
