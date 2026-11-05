---
id: screen-account-erased
type: screen
title: Account data erased
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

# Account data erased — screen

## Purpose

Rendered instead of the dashboard when TrustNet delivered an `account.erased`
purge webhook for the user's PPID. It is the user-visible proof that the demo RP
processed the erasure: the local session and demo data are gone, and the screen
reports the delivery.

## Layout

- **Header** — “Your demo RP data was erased”.
- **Explanation** — “TrustNet sent an account erasure webhook. This demo RP
  deleted its session and stored demo data for the affected subject.”
- **Delivery card** — event (`account.erased`), reason (`user_erasure`),
  `delivery_id`, received time, and the affected `sub` (PPID).
- **Primary action** — “Start over” to `screen-demo-home`.
- **Secondary action** — “Open webhook log” to `screen-webhook-log`.

## Copy

| Element | Copy (placeholder form) | Pinned |
| --- | --- | --- |
| Page heading | "Your demo RP data was erased" | yes |
| Explanation | "TrustNet sent an account erasure webhook. This demo RP deleted its session and stored demo data for the affected subject." | yes |
| Event label | "account.erased" | yes |
| Delivery label | "Delivery {delivery_id}" | no |
| Time label | "Received {time}" | no |
| Primary action | "Start over" | no |
| Secondary action | "Open webhook log" | no |

## Actions

| Action | Trigger | Result |
| --- | --- | --- |
| Start over | Click the primary action | `GET /` → `screen-demo-home` |
| Webhook log | Click the secondary action | `GET /webhooks` |

## Validation

- Rendered only when a stale session cookie resolves to an `erased` tombstone
  within the one-hour TTL.
- The delivery must have a valid Ed25519 JWS; unverified payloads never produce
  a tombstone.
- After the tombstone TTL, the cookie resolves to no session and `/` renders
  `screen-demo-home`.

## Navigation outcomes

| Outcome | Trigger | Next screen / exit |
| --- | --- | --- |
| Re-login | “Start over” | `screen-demo-home` |
| Webhook log | “Open webhook log” | `screen-webhook-log` |

## Edge cases

- **Unknown delivery** — a stale cookie with no matching tombstone falls back to
  `screen-demo-home`.
- **Repeated delivery** — the `delivery_id` is idempotent; the newest record is
  shown once.
- **Purge for a subject without a session** — the delivery still appears in
  `screen-webhook-log`; no tombstone exists for that browser.

## Open questions

- [ ] None.

## Changelog

| Date | Version | Change |
| --- | --- | --- |
| 2026-11-05 | 1.0.0 | Initial approved spec for the live demo RP. |
