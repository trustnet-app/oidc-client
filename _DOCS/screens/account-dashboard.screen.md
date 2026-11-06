---
id: screen-account-dashboard
type: screen
title: Account dashboard
status: approved
version: 1.1.0
updated: 2026-11-06
owners: [vladimir]
route: /account
area: dashboard
related:
  flows: []
  states: []
  sequences: []
  code: [main.go, handlers.go, result.go]
---

# Account dashboard — screen

## Purpose

The signed-in home of the demo RP. It proves the OIDC login worked and shows the
identity TrustNet disclosed: the header reads **“Logged in as
{preferred_username}”**. It is reached after the callback and whenever a
signed-in visitor opens `/`.

## Layout

- **Header** — “Logged in as {preferred_username}”, demo label, links to
  `/webhooks` and `/logout`, an **Escalate** action in the signed-in navbar, and
  a “Sign out” action.
- **Session card** — session start and expiry, `sub` (PPID), `sid` when present,
  and the age of the session.
- **Identity card** — preferred username, name, email, and the other decoded ID
  token claims.
- **OIDC UserInfo card** — the `/userinfo` response, or the error.
- **Machine plane card** — “TrustNet machine-plane userinfo” probe button, shown
  only when `MACHINE_URL` is configured.
- **Flow card** — “View last flow” link to `screen-flow-result` and the
  authorization-request preview link.
- **Events card** — the most recent back-channel logout / purge event that
  affected this session, if any.

## Copy

| Element | Copy (placeholder form) | Pinned |
| --- | --- | --- |
| Page heading | "Logged in as {preferred_username}" | yes |
| Session label | "Session" | no |
| Identity label | "Identity from the ID token" | no |
| UserInfo label | "OIDC /userinfo" | no |
| Probe label | "TrustNet machine-plane userinfo" | no |
| Probe action | "Test userinfo endpoint" | no |
| Flow action | "View last flow" | no |
| Escalate action | "Escalate" | yes |
| Sign out | "Sign out" | no |
| No username fallback | "{name}" then "{email}" then "{sub}" | yes |

## Actions

| Action | Trigger | Result |
| --- | --- | --- |
| View last flow | Click “View last flow” | `GET /result?state={state}` → `screen-flow-result` |
| Escalate | Click “Escalate” in the navbar | `GET /escalate` → `screen-escalation-request` |
| Test userinfo endpoint | Click the probe button (POST `/rp-userinfo`) | Re-renders this screen with the machine-plane response |
| Sign out | Click “Sign out” | `GET /logout` clears the local session and redirects to `screen-demo-home` |
| Open webhook log | Header link | `GET /webhooks` |
| Preview request | Link | `GET /start?preview=1` reuses the last request shape |

## Validation

- Every action requires a valid session; otherwise the request is rejected with
  `screen-error` (`401`).
- The **Escalate** navbar action is rendered only for a valid session.
- The probe requires `MACHINE_URL`; without it the card is hidden.
- The flow link is shown only when the session has a stored flow state.

## Navigation outcomes

| Outcome | Trigger | Next screen / exit |
| --- | --- | --- |
| Flow detail | “View last flow” | `screen-flow-result` |
| Escalation request | “Escalate” | `screen-escalation-request` |
| Signed out | “Sign out” | `screen-demo-home` |
| Session ended by TrustNet | Next request after back-channel logout | `screen-session-ended` |
| Account purged | Next request after purge | `screen-account-erased` |
| Expired session | Next request after the TTL | `screen-demo-home` (no session) |
| Error | Missing/invalid session on a protected action | `screen-error` |

## Edge cases

- **No `preferred_username`** — fall back to `name`, then `email`, then `sub`; the
  heading still says “Logged in as …”.
- **UserInfo failed** — the card shows the error; the session remains valid.
- **Probe unavailable after restart** — if the token was not persisted, the
  probe card explains that no access token is available.
- **Multiple tabs after logout** — the next action in any tab renders
  `screen-session-ended` or `screen-demo-home`.

## Open questions

- [ ] None.

## Changelog

| Date | Version | Change |
| --- | --- | --- |
| 2026-11-06 | 1.1.0 | Add the signed-in **Escalate** navbar action to `screen-escalation-request`. |
| 2026-11-06 | 1.0.1 | Sign out is local-only: clear the session and return to the home screen instead of redirecting to the issuer. |
| 2026-11-05 | 1.0.0 | Initial approved spec for the live demo RP. |
