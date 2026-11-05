---
id: screen-error
type: screen
title: Error
status: approved
version: 1.0.0
updated: 2026-11-05
owners: [vladimir]
route: any failing route
area: demo
related:
  flows: []
  states: []
  sequences: []
  code: [handlers.go]
---

# Error — screen

## Purpose

The shared failure surface for a missing session, an unknown/expired OIDC
`state`, an invalid callback, or a rejected probe. It explains what failed
without leaking tokens or claim values.

## Layout

- **Header** — “Something went wrong”.
- **Status line** — the HTTP status and a short, human-readable reason.
- **Detail card** — the sanitized error text (no tokens, cookies, or claim
  values).
- **Primary action** — “Back to home” to `screen-demo-home`.
- **Secondary action** — “Open dashboard” when a session is still valid.

## Copy

| Element | Copy (placeholder form) | Pinned |
| --- | --- | --- |
| Page heading | "Something went wrong" | yes |
| Status line | "{status} · {reason}" | no |
| Detail label | "Details" | no |
| Primary action | "Back to home" | no |
| Secondary action | "Open dashboard" | no |

## Actions

| Action | Trigger | Result |
| --- | --- | --- |
| Back to home | Click the primary action | `GET /` → `screen-demo-home` |
| Open dashboard | Click the secondary action | `GET /account` (only when a session exists) |

## Validation

- The status is one of `400` (bad request / unknown state), `401` (no session),
  `405` (wrong method), or `500` (unexpected server error).
- The detail is sanitized: no token, cookie, authorization code, or claim value.

## Navigation outcomes

| Outcome | Trigger | Next screen / exit |
| --- | --- | --- |
| Home | “Back to home” | `screen-demo-home` |
| Dashboard | “Open dashboard” | `screen-account-dashboard` |

## Edge cases

- **Unknown state** — likely an expired or replayed callback; “Back to home”
  starts a fresh flow.
- **No session** — the dashboard action is hidden.
- **Wrong method** — the status line names the allowed method.

## Open questions

- [ ] None.

## Changelog

| Date | Version | Change |
| --- | --- | --- |
| 2026-11-05 | 1.0.0 | Initial approved spec for the live demo RP. |
