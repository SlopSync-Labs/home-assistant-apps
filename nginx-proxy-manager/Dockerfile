# Use the official Nginx Proxy Manager image directly.
# BUILD_FROM is declared to satisfy HA's build tooling but not used —
# we want the full NPM image, not the minimal HA base.
ARG BUILD_FROM
FROM jc21/nginx-proxy-manager:2.14.0

# Redirect Let's Encrypt certificate storage into the persistent /data volume
# so certs survive add-on restarts and updates.
RUN mkdir -p /data/letsencrypt \
    && rm -rf /etc/letsencrypt \
    && ln -s /data/letsencrypt /etc/letsencrypt

COPY run.sh /run.sh
RUN chmod a+x /run.sh

EXPOSE 80 81 443

CMD [ "/run.sh" ]
