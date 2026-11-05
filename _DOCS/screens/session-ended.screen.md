---
id: screen-session-ended
type: screen
title: Session ended by TrustNet
status: approved
version: 1.0.0
updated: 2026-11-05
owners: [vladimir]
route: /account (stale cookie)
area: dashboard
related:
  flows: []
  states: []
  sequences: []
  code: [handlers.go]
---

# Session ended by TrustNet — screen

## Purpose

Rendered instead of the dashboard when the browser still holds a demo cookie but
the corresponding session was ended by TrustNet — either a back-channel logout
(`logged_out`) or an `access.revoked` purge event. It makes the server-to-server
logout visible: the user sees that TrustNet's action reached the demo RP.

## Layout

- **Header** — “You were signed out by TrustNet”.
- **Reason card** — event kind (`Back-channel logout` or `Access revoked`),
  received time, and the affected `sub`.
- **Explanation** — “The demo RP session ended because TrustNet notified it
  server-to-server. Your browser cookie is no longer valid.”
- **Primary action** — “Log in again” to `screen-demo-home`.
- **Secondary action** — “Open webhook log” to `screen-webhook-log`.

## Copy

| Element | Copy (placeholder form) | Pinned |
| --- | --- | --- |
| Page heading | "You were signed out by TrustNet" | yes |
| Explanation | "The demo RP session ended because TrustNet notified it server-to-server. Your browser cookie is no longer valid." | yes |
| Event label | "Back-channel logout" / "Access revoked" | no |
| Time label | "Received {time}" | no |
| Primary action | "Log in again" | no |
| Secondary action | "Open webhook log" | no |

## Actions

| Action | Trigger | Result |
| --- | --- | --- |
| Log in again | Click the primary action | `GET /` → `screen-demo-home` |
| Webhook log | Click the secondary action | `GET /webhooks` |

## Validation

- Rendered only when a stale session cookie resolves to a `logged_out` or
  `revoked` tombstone within the one-hour TTL.
- After the tombstone TTL, the cookie resolves to no session and `/` renders
  `screen-demo-home` instead.

## Navigation outcomes

| Outcome | Trigger | Next screen / exit |
| --- | --- | --- |
| Re-login | “Log in again” | `screen-demo-home` |
| Webhook log | “Open webhook log” | `screen-webhook-log` |

## Edge cases

- **Both back-channel and purge** — the newest event wins; the card names it.
- **Cookie absent** — no tombstone lookup; the home form renders.
- **Stale cookie after TTL** — no tombstone; normal logged-out home.

## Open questions

- [ ] None.

## Changelog

| Date | Version | Change |
| --- | --- | --- |
| 2026-11-05 | 1.0.0 | Initial approved spec for the live demo RP. |
