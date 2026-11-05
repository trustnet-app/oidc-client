# Demo RP — approved plan

Status legend: `[ ]` planned · `[~]` in progress / awaiting confirmation ·
`[x]` done · `[!]` blocked.

Owner-approved 2026-11-05. One part at a time; stop for confirmation after each.

## Goal

Turn the inspector into a small live demo relying party: OIDC login creates a
server-side session, `/` opens the dashboard when logged in, TrustNet
back-channel logout ends that session, and purge webhooks visibly demonstrate
revocation and erasure. All demo state lives in SQLite and expires after one
hour.

## Owner decisions

1. **Purge visibility:** A + B — a stale-cookie erased/ended screen *and* a
   `/webhooks` delivery log.
2. **Token persistence:** store `id_token` / `access_token` in the session row
   for the one-hour lifetime (needed for `id_token_hint` and the machine-plane
   probe after a restart).
3. **Purge response semantics:** `200` for verified deliveries; `400` for
   malformed/invalid bodies unless `PURGE_STRICT=false`, in which case the
   failure is recorded and `200` is returned.
4. **Deployment:** public HTTPS URLs will be registered for the callback,
   back-channel logout, and purge webhook.

## Parts

### [x] Part 1 — specification and visual catalogue

- `_DOCS/AGENTS.md`, `_DOCS/index.md`, `_DOCS/plan.md`.
- `_DOCS/screens/` — eight approved screen specs.
- `_DESIGN/` — static HTML/CSS/JS catalogue mirroring every screen.
- **Exit:** every screen doc has a matching rendering; internal links resolve.

**Landed 2026-11-05:** eight specs (`home`, `account-dashboard`,
`flow-result`, `auth-preview`, `session-ended`, `account-erased`,
`webhook-log`, `error`) registered in `_DOCS/index.md`, plus the static
`_DESIGN` catalogue (catalogue hub, shared `styles.css` with light/dark tokens,
`design.js`, and eight renderings). Verified: frontmatter/sections present, IDs
unique, registry links resolve, all `_DESIGN` internal links resolve. No Go code
changed. Awaiting owner confirmation before Part 2.

### [ ] Part 2 — persistence, config, TTL

- Add `modernc.org/sqlite`.
- `store.go`: `sessions`, `session_events`, `webhook_deliveries` tables created
  on startup.
- Config: `DB_PATH`, `SESSION_TTL` (default `1h`), `COOKIE_SECURE`,
  `PURGE_STRICT`.
- Sweeper prunes expired rows and old in-memory flows.
- Session cookie: random id, SHA-256 stored, `HttpOnly`, `SameSite=Lax`,
  `Secure` when configured.

### [ ] Part 3 — login, dashboard, home redirect

- `/callback` creates the session and redirects to `/account`.
- `/` redirects to `/account` when a session is valid.
- `/account` renders “Logged in as {preferred_username}” plus claim, userinfo,
  probe, and logout cards.
- `/result` and `/rp-userinfo` become session-scoped.
- `/logout` clears the local session then redirects to `end_session_endpoint`.

### [ ] Part 4 — back-channel logout

- Serve `/backchannel` and `/backchannel-logout`.
- Validate `logout_token` claims (`iss`, `aud`, `iat`, `events`, `sub`/`sid`,
  no `nonce`); `400` on invalid.
- Delete sessions by `sid`, then `sub`; write a `logged_out` tombstone; `200`.

### [ ] Part 5 — purge webhooks

- Validate the Ed25519 JWS (cached JWKS) and payload
  (`event`, `client_id`, `subs`, `reason`, `delivery_id`).
- `access.revoked` and `account.erased` delete matching sessions and write
  `revoked` / `erased` tombstones.
- Record every delivery; expose `/webhooks` and `/debug/purge`.
- Stale-cookie visits render `screen-session-ended` or `screen-account-erased`.

### [ ] Part 6 — tests, docs, deployment

- Unit tests for the store/TTL, logout-token validation, purge JWS, route
  aliases, redirect behaviour, and tombstones.
- `go build`, `go vet`, `go test ./...`.
- README, `.env.*.example`, deployment notes (HTTPS, public URLs, persistent DB,
  single instance).

## Deliberately out of scope

- Multiple users, passwords, or local accounts beyond the OP login.
- Refresh tokens and token rotation.
- Horizontal scaling (SQLite is single-instance).
- Signature verification of the logout token (this remains an inspector).
