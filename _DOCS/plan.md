# Deployment plan — test RP on hpmini against production

Status: deployed 2026-11-06. Public health check passes; interactive OIDC
login/logout/purge validation remains.

## Target

- **Public hostname:** `test-rp.smileservices.dev`
- **Traffic path:** DNS → DigitalOcean droplet `159.89.12.141` → nginx →
  WireGuard `10.10.0.2` → hpmini (`bubu`, LAN `192.168.0.144`)
- **App port:** `37841` (verified free; `37840` is used by
  `docs.smileservices.dev`)
- **Environment:** TrustNet production (`id.trustnet.app`, `rp.trustnet.app`)
- **User:** dedicated system user `trustnet_test-rp`
- **App directory:** `/home/trustnet_test-rp/oidc-client/`
- **Exposure:** app listens only on `10.10.0.2:37841`; HTTPS terminates at the
  droplet. No new public port on hpmini; `ufw` is inactive there.

## Configuration

Use the existing `prod.env` credentials. The binary loads `.env` by default, so
deploy a copy of `prod.env` to the target as `.env` (mode `0600`). Do not commit
the deployed file or `prod.env`; both contain production credentials.

The deployed `.env` must differ from `prod.env` in these values:

```dotenv
# prod.env currently has LISTEN=:80, which binds every interface and conflicts
# with hpmini's existing port 80.
LISTEN=10.10.0.2:37841

DB_PATH=/home/trustnet_test-rp/oidc-client/demo-rp.db
COOKIE_SECURE=true
PURGE_STRICT=true
```

Keep the rest from `prod.env`:

```dotenv
WELL_KNOWN_URL=https://id.trustnet.app/.well-known/openid-configuration
CLIENT_ID=<from prod.env>
CLIENT_SECRET=<from prod.env>
REDIRECT_URI=https://test-rp.smileservices.dev/redirect
TOKEN_AUTH_METHOD=basic
LABEL=Test Relying Party
SESSION_TTL=1h
MACHINE_URL=https://rp.trustnet.app
JWKS_URL=https://rp.trustnet.app/api/v1/webhook/jwks
```

No `CA_FILE`: production endpoints use publicly trusted TLS.

## Prerequisites

1. A TrustNet **production** client with `client_secret_basic` and these public
   URLs registered:
   - redirect: `https://test-rp.smileservices.dev/redirect`
   - back-channel logout: `https://test-rp.smileservices.dev/backchannel`
   - purge webhook: `https://test-rp.smileservices.dev/purge`
2. `CLIENT_ID` / `CLIENT_SECRET` in `prod.env` are valid for that client.
3. `test-rp.smileservices.dev` already resolves to `159.89.12.141`.
4. WireGuard routes `10.10.0.1` ↔ `10.10.0.2`; verify from the droplet.

## Steps

1. **Build and verify.**
   - `go test ./...`, `go vet ./...`
   - `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/oidc_oauth2_client .`
   - Assets are embedded; the binary is self-contained.
2. **Create the runtime identity and directory on hpmini.**
   - `useradd --system --create-home --home-dir /home/trustnet_test-rp --shell /usr/sbin/nologin trustnet_test-rp`
   - Create `/home/trustnet_test-rp/oidc-client` (`0750`, owned by the user).
3. **Install files.**
   - Copy the binary (`0750`).
   - Copy `prod.env` to the app directory as `.env` (`0600`), applying the
     `LISTEN`, `DB_PATH`, `COOKIE_SECURE`, and `PURGE_STRICT` changes above.
   - Leave `ENV` unset so the binary loads `.env`.
4. **Install the systemd unit.**
   - `trustnet-test-rp.service`: `User`/`Group=trustnet_test-rp`,
     `WorkingDirectory=/home/trustnet_test-rp/oidc-client`, no `ENV` override,
     `ExecStart=…/oidc_oauth2_client`, `Restart=on-failure`.
   - Harden with `NoNewPrivileges=true`, `PrivateTmp=true`,
     `ProtectSystem=strict`, and write access limited to the app directory.
   - Enable, start, and inspect `journalctl -u trustnet-test-rp`.
5. **Verify locally on hpmini.**
   - `curl -fsS http://10.10.0.2:37841/healthz` returns `ok`.
   - Logs show the expected listen address; SQLite files appear under the app
     directory.
6. **Add the droplet reverse proxy.**
   - Create `/etc/nginx/sites-available/test-rp.smileservices.dev.conf` with
     `proxy_pass http://10.10.0.2:37841;` and `Host`, `X-Real-IP`,
     `X-Forwarded-For`, `X-Forwarded-Proto` headers.
   - Enable it, run `nginx -t`, reload nginx.
   - Issue TLS with `certbot --nginx -d test-rp.smileservices.dev`.
   - Verify `https://test-rp.smileservices.dev/healthz` from outside the LAN.
7. **End-to-end check against production.**
   - Login, `/redirect` callback, dashboard, and result pages over HTTPS.
   - RP-initiated logout and a TrustNet back-channel logout.
   - A production purge delivery visible at `/webhooks` and `/debug/purge`.
   - Restart the service and confirm sessions are read from SQLite.

## Landed (2026-11-06)

- Created system user `trustnet_test-rp` and `/home/trustnet_test-rp/oidc-client`.
- Installed the static binary and deployed `prod.env` as `.env` (`0600`) with
  `LISTEN=10.10.0.2:37841`, an absolute `DB_PATH`, `COOKIE_SECURE=true`, and
  `PURGE_STRICT=true`.
- Installed and enabled `trustnet-test-rp.service`; it is active and loads
  production discovery from `https://id.trustnet.app`.
- Created `/etc/nginx/sites-available/test-rp.smileservices.dev.conf` on the
  droplet, proxying to `http://10.10.0.2:37841`.
- Issued a Let's Encrypt certificate for `test-rp.smileservices.dev` (expires
  2027-02-04) and enabled the HTTP→HTTPS redirect.
- Verified `https://test-rp.smileservices.dev/healthz` returns `ok` and the
  HTTP endpoint redirects to HTTPS.
- Remaining: an interactive production login, back-channel logout, and purge
  delivery to confirm the registered client URLs and credentials end to end.

## Rollback

- Stop and disable `trustnet-test-rp`.
- Remove the nginx site and Certbot certificate for
  `test-rp.smileservices.dev`; reload nginx.
- Remove the user and `/home/trustnet_test-rp/oidc-client`.
- DNS and WireGuard need no change.

## Notes

- SQLite is single-instance; never run a second copy against the same DB.
- The app stays HTTP on the WireGuard interface; only nginx exposes TLS.
- If discovery fails, check the production client credentials and DNS/TLS to
  `id.trustnet.app`.
- No application code changes are planned.

## Change log

- 2026-11-06: RP-initiated `/logout` is now local-only. It clears the session
  cookie and store row, records the `rp_initiated` event, and redirects to `/`
  instead of TrustNet's `end_session_endpoint`. Deploy a rebuilt binary to pick
  this up.
