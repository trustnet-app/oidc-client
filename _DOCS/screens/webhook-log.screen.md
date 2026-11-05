---
id: screen-webhook-log
type: screen
title: Webhook deliveries
status: approved
version: 1.0.0
updated: 2026-11-05
owners: [vladimir]
route: /webhooks
area: demo
related:
  flows: []
  states: []
  sequences: []
  code: [handlers.go]
---

# Webhook deliveries — screen

## Purpose

The tester-facing proof that server-to-server notifications arrived. It lists
purge deliveries (`access.revoked`, `account.erased`) with verification status,
reason, affected PPIDs, and the delivery id. Back-channel logout events are
listed separately because they are not webhooks.

## Layout

- **Header** — “Webhook deliveries”, demo label, back to the dashboard or home.
- **Explanation** — “TrustNet signs each purge webhook with Ed25519. Verified
  rows were checked against the JWKS; invalid rows are recorded but not acted
  on.”
- **Purge delivery table** — received time, event, reason, `verified` badge,
  `delivery_id`, affected `subs`, and error text when unverified.
- **Back-channel logout table** — received time, `sid`, `sub`, and the decoded
  event.
- **Empty state** — “No deliveries yet. Revoke access or erase an account in
  TrustNet, then refresh.”
- **Actions** — “Refresh”, “Reset demo state” (`POST /debug/reset`), and
  “Open JSON” (`/debug/purge`).

## Copy

| Element | Copy (placeholder form) | Pinned |
| --- | --- | --- |
| Page heading | "Webhook deliveries" | no |
| Explanation | "TrustNet signs each purge webhook with Ed25519. Verified rows were checked against the JWKS; invalid rows are recorded but not acted on." | yes |
| Empty state | "No deliveries yet. Revoke access or erase an account in TrustNet, then refresh." | no |
| Verified badge | "verified" / "unverified" | no |
| Refresh action | "Refresh" | no |
| Reset action | "Reset demo state" | no |
| JSON action | "Open JSON" | no |

## Actions

| Action | Trigger | Result |
| --- | --- | --- |
| Refresh | Click “Refresh” | Re-render `GET /webhooks` |
| Reset demo state | Click “Reset demo state” | `POST /debug/reset`; reload the list |
| Open JSON | Click “Open JSON” | `GET /debug/purge` |

## Validation

- Public page; no session required (it contains only PPIDs, never tokens,
  cookies, or claim values).
- Unverified rows are shown with the verification error and are not used to
  delete sessions or write tombstones.

## Navigation outcomes

| Outcome | Trigger | Next screen / exit |
| --- | --- | --- |
| Dashboard | Header link when signed in | `screen-account-dashboard` |
| Home | Header link when signed out | `screen-demo-home` |
| JSON | “Open JSON” | `/debug/purge` |

## Edge cases

- **No deliveries** — the empty state renders.
- **JWKS unavailable** — deliveries are recorded `verified=false` with the
  fetch error; the page still renders.
- **Many deliveries** — the table is capped at the newest 100 within the
  one-hour TTL.

## Open questions

- [ ] None.

## Changelog

| Date | Version | Change |
| --- | --- | --- |
| 2026-11-05 | 1.0.0 | Initial approved spec for the live demo RP. |
