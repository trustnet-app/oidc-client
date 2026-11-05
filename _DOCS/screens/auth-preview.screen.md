---
id: screen-auth-preview
type: screen
title: Authorization request preview
status: approved
version: 1.0.0
updated: 2026-11-05
owners: [vladimir]
route: /start?preview=1
area: demo
related:
  flows: []
  states: []
  sequences: []
  code: [handlers.go, result.go]
---

# Authorization request preview — screen

## Purpose

Shows the exact authorization request before the browser is sent to TrustNet.
The flow state (state, nonce, PKCE verifier) is already stored, so “Continue”
navigates to the same URL `/start` would have redirected to.

## Layout

- **Header** — “Authorization request — {label}”.
- **Notice** — “Nothing has been sent yet. This is the exact request the browser
  will send to the issuer.”
- **Request URL card** — the full URL in a `<pre>`.
- **Decoded parameters card** — one row per query parameter.
- **Actions** — “Continue to issuer” and “Back”.

## Copy

| Element | Copy (placeholder form) | Pinned |
| --- | --- | --- |
| Page heading | "Authorization request — {label}" | no |
| Notice | "Nothing has been sent yet. This is the exact request the browser will send to the issuer." | yes |
| Primary action | "Continue to issuer" | no |
| Secondary action | "Back" | no |

## Actions

| Action | Trigger | Result |
| --- | --- | --- |
| Continue | Click the primary action | Navigate to the stored authorize URL |
| Back | Click “Back” | `GET /` → `screen-demo-home` |

## Validation

- The stored flow must exist; a missing or expired flow renders
  `screen-error`.
- No user input is accepted on this screen.

## Navigation outcomes

| Outcome | Trigger | Next screen / exit |
| --- | --- | --- |
| Authorize | “Continue to issuer” | Issuer authorize endpoint |
| Back | “Back” | `screen-demo-home` |
| Error | Flow expired | `screen-error` |

## Edge cases

- **Flow expired while previewing** — the continue link still points at the
  issuer; the callback then renders `screen-error` (`unknown state`).
- **Long request URL** — the `<pre>` scrolls horizontally.

## Open questions

- [ ] None.

## Changelog

| Date | Version | Change |
| --- | --- | --- |
| 2026-11-05 | 1.0.0 | Initial approved spec for the live demo RP. |
