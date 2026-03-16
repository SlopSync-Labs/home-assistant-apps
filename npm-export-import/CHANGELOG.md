<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to the NPM Export Import add-on will be documented here.

## [0.1.11] - 2026-03-15

### Changed

- Operations tab redesigned for consistency: file list rows are now selectable
  (click to highlight) with a single **Import Selected** button mirroring the
  **Export Now** button — no more per-row import buttons
- Operation status moved to a fixed-height bar above the cards so the page
  layout never shifts when status text appears or disappears
- Removed "Run against a fresh or cleared instance to avoid duplicates" note
  since duplicate handling is now automatic
- Import confirmation uses the single Import Selected button (turn red →
  Confirm? on first click, fires on second click within 3 s)

---

## [0.1.10] - 2026-03-15

### Fixed

- Proxy host import now PUTs (updates) existing entries instead of skipping on
  "already in use" — ensures `access_list_id` and `certificate_id` remapping is
  always applied even when the host was previously imported
- Proxy host deduplication uses a pre-fetched domain→id map so existing hosts
  are found without relying on error responses

---

## [0.1.9] - 2026-03-15

### Fixed

- Access list import logs client rule count from the NPM response so silent
  drops are detectable (`(N client rules)` in the log after each create/update)
- Stream import now checks for existing streams by `incoming_port` before
  creating — skips with a warning instead of duplicating

---

## [0.1.8] - 2026-03-15

### Fixed

- Access list import now PUTs (updates) existing entries instead of skipping
  them — ensures clients and items are always synced even when the access list
  was previously imported without the full data
- Access list import: removed debug payload logging now that 500 errors are resolved

---

## [0.1.7] - 2026-03-15

### Fixed

- Access list import: deduplication GET failure is now a warning rather than
  a hard abort; import continues without duplicate protection
- Access list import: payload is logged before the POST so 500 errors are
  diagnosable; uses `_check()` for consistent error handling and skip-on-conflict

---

## [0.1.6] - 2026-03-15

### Fixed

- Access list export now fetches `?expand=items,clients` so auth entries and IP
  rules are included in the backup (previously only the top-level metadata was exported)
- Access list import skips creation if an entry with the same name already exists
  on the target, reusing the existing ID for proxy host remapping instead of
  creating a duplicate
- Stream import payload reduced to the 5 fields the POST endpoint actually accepts
  (`incoming_port`, `forwarding_host`, `forwarding_port`, `tcp_forwarding`,
  `udp_forwarding`) — `enabled` and other fields cause a 400 on this endpoint

---

## [0.1.5] - 2026-03-15

### Fixed

- Import 400 errors on access lists, streams — replaced `_strip()` pass-through
  with explicit field allowlists to exclude NPM relation fields (e.g. `proxy_hosts`)
  that GET returns but POST rejects
- Reverted proxy host and redirection host import back to `_strip()` which was
  already working correctly
- Added `_check()` helper to log NPM's error response body on failed imports
  instead of only reporting the HTTP status code
- Settings tab: after saving, `/data/options.json` is now also written directly
  so `load_options()` returns fresh values without an add-on restart

---

## [0.1.4] - 2026-03-15

### Added

- Settings tab in the web UI — edit NPM connection details and schedule configuration
  without leaving the HA panel; changes are written back via the HA Supervisor API
  (`POST http://supervisor/addons/self/options`) and reflected in the HA add-on
  Configuration tab immediately
- `GET /api/config` endpoint — returns current add-on options with passwords masked
- `POST /api/config` endpoint — saves updated options via Supervisor API; password
  fields left blank are preserved unchanged (sentinel value pattern)
- `hassio_api: true` and `hassio_role: "default"` in `config.json` to enable
  Supervisor API access

---

## [0.1.3] - 2026-03-15

### Added

- Interactive 2FA popup — when a 2FA-protected NPM account is detected, a modal
  automatically appears asking for the authenticator code; after verification the
  pending operation auto-retries without any further user action
- `npm_token` config option — supply a pre-generated Bearer token to bypass
  interactive auth entirely; required for scheduled exports on 2FA-protected accounts
  since scheduled runs are unattended and cannot prompt for an OTP
- Server-side JWT session cache — a successful login (interactive or password-based)
  is cached for the token's lifetime (~24h) so repeated operations do not re-authenticate
- `POST /api/auth/verify2fa` Flask endpoint — receives the challenge token and OTP
  code, completes the NPM 2FA flow, and caches the resulting JWT

---

## [0.1.2] - 2026-03-15

### Fixed

- Added `bash` to the Dockerfile via `apk add --no-cache bash` — `python:3.11-alpine`
  ships with `ash` only; HA Supervisor invokes `run.sh` with bash, causing a startup crash
- Set `SHELL ["/bin/bash", "-c"]` so subsequent `RUN` steps use bash

---

## [0.1.1] - 2026-03-15

### Added

- Flask web server with HA ingress UI — export and import are now triggered
  via buttons in the add-on panel rather than config-driven one-shot runs
- **Export Now** button writes a timestamped JSON backup to
  `/share/npm-export-import/`
- **Import** button per backup file — restores entries into NPM in
  dependency order (certs → access lists → proxy hosts → redirections → streams)
- Live log panel in the UI, polling every 2 seconds
- `schedule_enabled` / `schedule_interval_hours` config options for
  automatic background exports while the web UI stays available
- SSL certificate export: Let's Encrypt cert files (fullchain + private key)
  read directly from the shared `/ssl/nginxproxymanager/live/npm-{id}/` volume
  and stored base64-encoded in the export bundle
- SSL certificate import: certs re-uploaded to target NPM instance via the
  certificate upload API; old-to-new ID remapping applied to all referencing hosts
- Access list import with old-to-new ID remapping for proxy host references
- Mutex-guarded background thread runner — only one operation runs at a time
- `ingress: true` and `ingress_port: 8099` in `config.json`
- `map: ["share:rw", "ssl:rw"]` for export file storage and cert file access

---

## [0.1.0] - 2026-03-15

### Added

- Initial scaffold for the NPM Export Import add-on
