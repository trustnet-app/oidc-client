# oidc_oauth2_client

A standalone OIDC Relying Party **inspector** for testing TrustNet staging and
production. Server-rendered, authorization-code + PKCE, configured entirely from
a `.env` file. Endpoints come from the environment's OIDC discovery document, so
one binary targets any deployment.

Derived from TrustNet's `_DEV/mock-rp` fixture. Like it, this is a **test tool**:
it decodes JWTs without verifying signatures. It is an inspector, not a
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

Then open <http://localhost:5556/>, pick scopes/claims, and start the flow.

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
| `/backchannel-logout` | receives logout tokens |
| `/purge` | receives TrustNet purge webhooks (verify needs `JWKS_URL`) |
| `/debug/state`, `/debug/purge`, `/debug/reset` | machine-readable state |

## Notes

- Sessions, lifecycle events, and purge deliveries live in SQLite at `DB_PATH`
  and are pruned after `SESSION_TTL`.
- The live pages embed `_DESIGN/styles.css` and `_DESIGN/design.js` and serve
  them as `/styles.css` and `/design.js`, so the app and the screen catalogue
  share one visual language.
- The RP's `sub` is the PPID; `account_id`/`persona_id` must never appear.
- The registered `REDIRECT_URI` must exist on the client in each environment;
  this tool deliberately does **not** create or update clients.
