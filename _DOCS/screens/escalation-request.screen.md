---
id: screen-escalation-request
type: screen
title: Escalation request
status: review
version: 0.1.0
updated: 2026-11-06
owners: [vladimir]
route: /escalate
area: dashboard
related:
  flows: []
  states: []
  sequences: []
  code: [handlers.go, account.go, result.go]
---

# Escalation request — screen

## Purpose

Lets a signed-in user ask TrustNet for claims the current demo session does not
have yet. The RP sends a fresh authorization request with the previously shared
claims plus the new selection and `prompt=consent`. TrustNet treats the grown
claim set as an escalation: it forces a full consent review and pre-fills the
claims the persona already shared. When the browser returns, `screen-flow-result`
shows which requested claims were returned and which were not.

## Layout

- **Header** — the shared signed-in navbar, with **Escalate** marked current.
- **Intro** — explains that the request adds claims to the current session and
  that TrustNet will review them before sharing.
- **Already shared card** — the claim names the current session already holds,
  rendered as read-only badges. These claims are carried into the new request
  automatically and cannot be deselected on this screen.
- **Additional claims card** — a checkbox group of requestable claims not already
  present in the session. Nothing is pre-checked. Protocol claims (`iss`, `sub`,
  `aud`, `exp`, `iat`, `sid`, `nonce`) are never offered.
- **Notice** — “This sends a new authorization request to TrustNet. The claims
  already shared with this RP are carried over; only the new claims need review.”
- **Actions** — “Continue to TrustNet” (primary) and “Cancel” (secondary).
- **Empty state** — when every requestable claim is already shared, the card says
  “Every available claim is already shared with this RP.” and the primary action
  is hidden.

## Copy

| Element | Copy (placeholder form) | Pinned |
| --- | --- | --- |
| Page heading | "Request more claims from TrustNet" | no |
| Navbar action | "Escalate" | yes |
| Already shared label | "Already shared" | no |
| Additional claims label | "Request additional claims" | no |
| Additional claims hint | "Select the new claims you want TrustNet to review. Previously shared claims are carried over automatically." | no |
| Notice | "This sends a new authorization request to TrustNet. The claims already shared with this RP are carried over; only the new claims need review." | yes |
| Primary action | "Continue to TrustNet" | no |
| Secondary action | "Cancel" | no |
| Empty state | "Every available claim is already shared with this RP." | no |

## Actions

| Action | Trigger | Result |
| --- | --- | --- |
| Continue to TrustNet | Submit the form | `GET /start` with the carried-over and selected claim names, `scope=openid`, and `prompt=consent`; the flow is recorded as an escalation for the return comparison, then the browser is redirected to the issuer authorize endpoint |
| Cancel | Click “Cancel” | `GET /account` → `screen-account-dashboard` |

## Validation

- Requires a valid session; otherwise the request is rejected with
  `screen-error` (`401`).
- At least one new claim must be selected; a submission with none is rejected
  with `screen-error` (`400`).
- The request carries exactly the current session claim names plus the selected
  new names. The user cannot remove an already-shared claim from this screen.
- The flow stores the requested claim names for the return comparison. Claim
  values are never stored for this purpose and never logged.
- `prompt=consent` is always sent. A grown claim set already forces full review
  in TrustNet; the parameter keeps the request standard-compliant.

## Navigation outcomes

| Outcome | Trigger | Next screen / exit |
| --- | --- | --- |
| Authorize | “Continue to TrustNet” | Issuer authorize endpoint |
| Cancel | “Cancel” | `screen-account-dashboard` |
| Session ended | Request after logout or expiry | `screen-session-ended` / `screen-demo-home` |
| Error | Missing session or no new claim | `screen-error` |

## Edge cases

- **Every claim already shared** — the empty state renders; no request can be
  started from this screen.
- **Session expires while the form is open** — submitting rejects with
  `screen-error` (`401`); the user must sign in again.
- **TrustNet denies or cancels the review** — the RP keeps the existing session
  unchanged and `screen-flow-result` shows the issuer error instead of the
  outcome table.
- **A requested claim is unavailable** — TrustNet may omit a claim the user
  approved when the selected persona has no value for it. The result reports the
  claim as “Not returned” because OIDC gives the RP no reason.
- **A claim is not registered for the client** — TrustNet may reject the
  authorization request (`invalid_request` / `invalid_scope`); the flow result
  shows the issuer error.
- **Two escalation tabs** — the callback that completes last replaces the session;
  both flow results remain inspectable.

## Open questions

- [ ] Should the demo allow removing an already-shared claim on this screen, or
      keep escalation additive only? The current spec is additive.
- [ ] Should the result distinguish “declined by the user” from “no value at
      TrustNet”? The RP cannot observe that difference, so the current spec
      reports “Not returned”.

## Changelog

| Date | Version | Change |
| --- | --- | --- |
| 2026-11-06 | 0.1.0 | Proposed escalation-request screen for signed-in users. |
