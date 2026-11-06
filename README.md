# oidc_oauth2_client

A standalone OIDC Relying Party **inspector** for testing TrustNet staging and
production. Server-rendered, authorization-code + PKCE, configured entirely from
a `.env` file. Endpoints come from the environment's OIDC discovery document, so
one binary targets any deployment.

Derived from TrustNet's `_DEV/mock-rp` fixture. Like it, this is a **test tool**:
ID tokens and logout tokens are decoded without signature verification, while
purge webhooks are verified against the JWKS. It is an inspector, not a
validator, and it never self-registers a client — registration stays in each
environment's seed path.

## Config

Copy a template and fill it in:

```bash
cp .env.staging.example .env.staging       # or .env.production.example
$EDITOR .env.staging
```

| Variable | Required | Notes |
|---|---|---|
| `WELL_KNOWN_URL` | yes | discovery document; or set `ISSUER` to derive it |
| `CLIENT_ID` | yes | RP client registered in that environment |
| `CLIENT_SECRET` | yes | used by the client's registered auth method |
| `REDIRECT_URI` | yes | must be registered on the client (default `http://localhost:5556/callback`) |
| `TOKEN_AUTH_METHOD` | no | `post` (default) or `basic`; must match the client's `token_endpoint_auth_method`. Portal-registered production RPs use `client_secret_basic`. |
| `LISTEN` | no | default `:5556` |
| `LABEL` | no | shown on screen / in `/debug/state` |
| `DB_PATH` | no | SQLite demo store, default `demo-rp.db` |
| `SESSION_TTL` | no | demo state lifetime, default `1h` |
| `COOKIE_SECURE` | no | add `Secure` to the session cookie when served over HTTPS |
| `PURGE_STRICT` | no | default `true`; invalid purge bodies get `400`, `false` records and returns `200` |
| `MACHINE_URL` | no | enables the machine-plane `/userinfo` probe when set |
| `JWKS_URL` | no | enables purge-webhook JWS verification when set |
| `CA_FILE` | no | add a PEM root (staging's internal CA) |
| `TLS_INSECURE` | no | dev-only escape hatch; warns loudly |

`ENV=<name>` selects `.env.<name>`; with `ENV` unset, `.env` is loaded. Real
environment variables always override the file.

## Run

```bash
./run.sh staging       # loads .env.staging, http://localhost:5556
./run.sh production    # loads .env.production
./run.sh               # loads .env
```

Then open <http://localhost:5556/>, pick scopes/claims, and start the flow. A
successful callback creates the demo session and lands on `/account`.

## Routes

| Route | Purpose |
|---|---|
| `/` | launch form; redirects to `/account` when a valid session exists |
| `/start` | build the authorize URL (`?preview=1` renders it instead of following) |
| `/callback` | code exchange, ID-token decode, session creation, OIDC `/userinfo` |
| `/account` | signed-in dashboard (session, identity, userinfo, probe, flow, events) |
| `/result` | session-scoped per-flow result surface |
| `/rp-userinfo` | session-scoped machine-plane `/api/rp/v1/userinfo` probe (needs `MACHINE_URL`) |
| `/logout` | clears the local session, then redirects to `end_session_endpoint` |
| `/backchannel`, `/backchannel-logout` | validates logout-token claims and ends matching sessions |
| `/purge` | verifies Ed25519 purge webhooks and ends/erases matching sessions |
| `/webhooks` | public purge-delivery and back-channel logout log |
| `/debug/state`, `/debug/purge`, `/debug/reset` | machine-readable state |

## Tests

```bash
go test ./...
go vet ./...
go build ./...
```

The suite covers the SQLite store and TTL pruning, session cookies, logout-token
validation, purge JWS verification and strict/non-strict responses, route
aliases, redirects, session scoping, and tombstones.

## Deployment

- Serve behind HTTPS and set `COOKIE_SECURE=true`.
- Register the public callback (`REDIRECT_URI`), back-channel logout, and purge
  URLs with TrustNet. Logout and purge must be reachable server-to-server.
- Put `DB_PATH` on a persistent volume. SQLite is single-instance: run exactly
  one process per database and do not scale horizontally.
- Keep `SESSION_TTL` at `1h` for the demo; the sweeper prunes sessions, events,
  and deliveries on that TTL.
- Set `JWKS_URL` so purge webhooks can be verified. Use `PURGE_STRICT=false` only
  when invalid deliveries should be recorded instead of rejected with `400`.
- `MACHINE_URL` enables the machine-plane `/userinfo` probe on the dashboard and
  result page.

## Notes

- Sessions, lifecycle events, and purge deliveries live in SQLite at `DB_PATH`
  and are pruned after `SESSION_TTL`.
- Session cookies carry only a random id; SQLite stores its SHA-256 hash.
- Logout tokens are claim-validated but not signature-verified (inspector).
  Purge webhooks are signature-verified against a cached JWKS (5-minute TTL,
  refreshed when an unknown `kid` appears).
- `/webhooks` is public and shows only PPIDs and delivery metadata — never
  tokens, cookies, or claim values.
- The live pages embed `_DESIGN/styles.css` and `_DESIGN/design.js` and serve
  them as `/styles.css` and `/design.js`, so the app and the screen catalogue
  share one visual language.
- The RP's `sub` is the PPID; `account_id`/`persona_id` must never appear.
- The registered `REDIRECT_URI` must exist on the client in each environment;
  this tool deliberately does **not** create or update clients.
