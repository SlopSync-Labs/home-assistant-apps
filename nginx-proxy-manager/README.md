# Nginx Proxy Manager

Expose your services easily and securely with a beautiful web GUI for Nginx.
This add-on runs the **latest upstream** [jc21/nginx-proxy-manager](https://github.com/NginxProxyManager/nginx-proxy-manager) image (currently v2.14.0).

## Features

- Free SSL via Let's Encrypt (HTTP-01 and DNS-01 challenges)
- Reverse proxy with custom locations, websocket support, and access lists
- Redirect and 404 hosts
- Beautiful web UI on port 81

## Ports

| Port | Protocol | Description         |
|------|----------|---------------------|
| 80   | TCP      | HTTP proxy traffic  |
| 81   | TCP      | Admin web UI        |
| 443  | TCP      | HTTPS proxy traffic |

## First-run credentials

On first start, log in to the admin UI at `http://<your-ha-ip>:81` with:

- **Email:** `admin@example.com`
- **Password:** `changeme`

You will be prompted to change both immediately after login.

## Data persistence

All NPM data (database, proxy configuration, Let's Encrypt certificates) is stored in
the add-on's `/data` directory, which is mapped to HA's persistent add-on data store.
Certificates are kept at `/data/letsencrypt` and will survive restarts and updates.

## Upgrading

To track a new NPM release, update the `FROM` line in `Dockerfile` and bump `version`
in `config.json` to match the new upstream tag (e.g. `2.15.0`).

## Notes

- Ports 80 and 443 must be free on the host — disable HA's built-in nginx if it occupies them.
- This add-on does **not** use a HA base image; it uses the official NPM Docker image directly.

## Logo

The `icon.png` used by this add-on is the official Nginx Proxy Manager logo,
sourced from the [NginxProxyManager/nginx-proxy-manager](https://github.com/NginxProxyManager/nginx-proxy-manager)
repository. All logo rights belong to the Nginx Proxy Manager contributors.
