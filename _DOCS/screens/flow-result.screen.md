---
id: screen-flow-result
type: screen
title: Flow result
status: approved
version: 1.1.1
updated: 2026-11-06
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
the dashboard and from the callback's post/redirect/get landing. For an
escalation flow it is also the return surface: an **Escalation outcome** card
compares the requested claim names with the claims TrustNet actually returned.

## Layout

- **Header** — “Flow result”, demo label, back to the dashboard.
- **Outcome card** — success, denial (`error`, `error_description`), or token
  exchange failure.
- **Escalation outcome card** — only for an escalation flow: a table of every
  requested claim with its source (“Already shared” or “New request”) and
  whether TrustNet returned it (“Shared” or “Not returned”), plus a
  “{returned} of {requested} requested claims returned” summary.
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
| Escalation outcome label | "Escalation outcome" | no |
| Escalation summary | "{returned} of {requested} requested claims returned" | no |
| Escalation statuses | "Shared" / "Not returned" | no |
| Escalation sources | "Already shared" / "New request" | no |
| Escalation account mismatch | "The authorization returned a different account. Use the same account as the current session." | yes |
| New flow action | "New flow" | no |

## Actions

| Action | Trigger | Result |
| --- | --- | --- |
| Test userinfo endpoint | POST `/rp-userinfo` | Re-renders with the machine-plane response |
| New flow | Click “New flow” | `GET /` → `screen-demo-home` |
| Open debug state | Link | `GET /debug/state` (JSON) |

## Validation

- Requires a valid session and a known `state`; otherwise `screen-error`.
- The escalation outcome card appears only when the flow recorded an escalation
  request. It compares the requested claim names with the claims present in the
  ID token and OIDC `/userinfo`; protocol claims are ignored. The card shows
  names and statuses only, never claim values.
- A requested claim absent from both the ID token and `/userinfo` is “Not
  returned”. OIDC does not tell the RP whether the user declined it or TrustNet
  had no value, so the demo does not claim to know why.
- For an escalation, a returned `sub` that differs from the session that started
  it is rejected. The error card renders “Use the same account as the current
  session.”, the returned claims are discarded, and no outcome card is shown.
- Token values are never rendered in HTML; only `/debug/state` exposes them.
- The probe requires an access token and `MACHINE_URL`.

## Navigation outcomes

| Outcome | Trigger | Next screen / exit |
| --- | --- | --- |
| Escalation return | Callback completes an escalation flow | `GET /result?state={state}` → `screen-flow-result` |
| New flow | “New flow” | `screen-demo-home` |
| Dashboard | Header link | `screen-account-dashboard` |
| Error | Unknown state or missing session | `screen-error` |

## Edge cases

- **Denied authorization** — the error card renders `error` and
  `error_description`; no token card and no escalation outcome card.
- **Token exchange failure** — the error card renders the issuer response.
- **No userinfo endpoint** — the UserInfo card is hidden; the escalation outcome
  falls back to the ID token claims only.
- **Every requested claim returned or none returned** — the summary states the
  count and the table renders every requested claim.
- **A previously shared claim is not returned** — it is listed as “Not returned”
  even though it was not newly selected.
- **Different account during escalation** — the RP keeps the old session,
  discards the returned claims, and renders the account-mismatch error; the
  escalation outcome card is absent.
- **Unexpected returned claim** — a claim TrustNet returns that the RP did not
  request is not added to the escalation table; it remains visible in the ID
  token and UserInfo cards.

## Open questions

- [ ] None.

## Changelog

| Date | Version | Change |
| --- | --- | --- |
| 2026-11-06 | 1.1.1 | Add the escalation account-mismatch error and document that the returned claims are discarded. |
| 2026-11-06 | 1.1.0 | Add the escalation outcome card and the escalation callback return path. |
| 2026-11-05 | 1.0.0 | Initial approved spec for the live demo RP. |
