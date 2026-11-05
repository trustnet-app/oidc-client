---
id: screen-flow-result
type: screen
title: Flow result
status: approved
version: 1.0.0
updated: 2026-11-05
owners: [vladimir]
route: /result
area: demo
related:
  flows: []
  states: []
  sequences: []
  code: [handlers.go, result.go]
---

# Flow result — screen

## Purpose

The per-flow inspector surface: the decoded ID token, the OIDC `/userinfo`
response, the token metadata, and the machine-plane probe. It is reached from
the dashboard and from the callback's post/redirect/get landing.

## Layout

- **Header** — “Flow result”, demo label, back to the dashboard.
- **Outcome card** — success, denial (`error`, `error_description`), or token
  exchange failure.
- **Subject card** — `sub` (PPID) prominently.
- **ID token claims card** — decoded claims as pretty JSON.
- **UserInfo card** — the `/userinfo` response or error.
- **Token card** — token keys and expiry, with values redacted.
- **Machine plane card** — probe button and the last request/response, when
  configured.
- **Footer** — “New flow” back to `screen-demo-home` and a link to
  `/debug/state`.

## Copy

| Element | Copy (placeholder form) | Pinned |
| --- | --- | --- |
| Page heading | "Flow result" | no |
| Subject label | "sub (PPID)" | yes |
| ID token label | "ID token claims" | no |
| UserInfo label | "OIDC /userinfo" | no |
| Token label | "Token response (values redacted)" | no |
| Error label | "Error" | no |
| New flow action | "New flow" | no |

## Actions

| Action | Trigger | Result |
| --- | --- | --- |
| Test userinfo endpoint | POST `/rp-userinfo` | Re-renders with the machine-plane response |
| New flow | Click “New flow” | `GET /` → `screen-demo-home` |
| Open debug state | Link | `GET /debug/state` (JSON) |

## Validation

- Requires a valid session and a known `state`; otherwise `screen-error`.
- Token values are never rendered in HTML; only `/debug/state` exposes them.
- The probe requires an access token and `MACHINE_URL`.

## Navigation outcomes

| Outcome | Trigger | Next screen / exit |
| --- | --- | --- |
| New flow | “New flow” | `screen-demo-home` |
| Dashboard | Header link | `screen-account-dashboard` |
| Error | Unknown state or missing session | `screen-error` |

## Edge cases

- **Denied authorization** — the error card renders `error` and
  `error_description`; no token card.
- **Token exchange failure** — the error card renders the issuer response.
- **No userinfo endpoint** — the UserInfo card is hidden.

## Open questions

- [ ] None.

## Changelog

| Date | Version | Change |
| --- | --- | --- |
| 2026-11-05 | 1.0.0 | Initial approved spec for the live demo RP. |
