---
id: screen-demo-home
type: screen
title: Demo RP home / launch
status: approved
version: 1.1.0
updated: 2026-11-05
owners: [vladimir]
route: /
area: demo
related:
  flows: []
  states: []
  sequences: []
  code: [main.go, handlers.go]
---

# Demo RP home / launch — screen

## Purpose

The public entry point. An unauthenticated visitor configures the OIDC request
here and starts the authorization-code + PKCE flow. A visitor with a valid demo
session never sees this screen: `/` redirects to `screen-account-dashboard`.

## Layout

- **Header** — demo label, current issuer, and a link to `/webhooks`.
- **Intro** — one short paragraph explaining the demo and the
  authorization-code flow.
- **Identity line** — `client_id`, registered `redirect_uri`, issuer.
- **Scope** — checkbox group containing `openid` only, checked by default.
- **Claims** — a single checkbox group listing every available claim; the demo
  user may register or deregister any of them. Pre-checked: `email`,
  `email_verified`, `given_name`, `family_name`.
- **prompt** — checkbox for `consent`.
- **Raw `claims` parameter** — optional JSON textarea that overrides the claim
  checkboxes.
- **Actions** — “Start login” (submit) and “Preview request”
  (`/start?preview=1`).

## Copy

| Element | Copy (placeholder form) | Pinned |
| --- | --- | --- |
| Page title | "{label}" | no |
| Eyebrow | "Authorization Code Flow · Demo Client" | no |
| Intro | "This demo relying party signs you in with OpenID Connect. Choose the claims to request, then start the authorization-code flow." | no |
| Identity line | "client_id {client_id} · redirect {redirect_uri} · issuer {issuer}" | no |
| Primary action | "Start login" | no |
| Secondary action | "Preview request" | no |
| Scope legend | "Scope" | no |
| Scope badge | "OAuth 2.0 / OIDC" | no |
| Scope required tag | "required" | no |
| Claims legend | "Claims" | no |
| Claims meta | "Standard OpenID Spec" | no |
| Claims hint | "Select any claims to request. Every claim below can be registered or deregistered for this demo client." | no |
| Prompt meta | "Interaction Control" | no |
| Claims editor meta | "JSON Editor" | no |
| Claims editor file label | "claims_payload.json" | no |
| Logged-in note | "You are signed in — open the dashboard." | no |

## Actions

| Action | Trigger | Result |
| --- | --- | --- |
| Start login | Submit the form | `GET /start` builds the authorize URL and redirects the browser to the issuer |
| Preview request | Submit with `preview=1` | `GET /start?preview=1` renders `screen-auth-preview`; flow state is stored |
| Open dashboard | Click the logged-in note | `GET /account` |
| Open webhook log | Header link | `GET /webhooks` |

## Validation

- The scope list contains `openid` only; it is always requested.
- Selected claims are requested through the `claims` parameter; the raw
  `claims` textarea wins over the checkboxes when non-empty.
- The issuer and `client_id` are server-provided; the form posts only choices.

## Navigation outcomes

| Outcome | Trigger | Next screen / exit |
| --- | --- | --- |
| Authorize | Start login | Issuer authorize endpoint |
| Preview | Preview request | `screen-auth-preview` |
| Already signed in | `GET /` with a valid session | `screen-account-dashboard` |
| Webhooks | Header link | `screen-webhook-log` |

## Edge cases

- **Expired session** — the home form is shown; no error is raised.
- **Missing discovery** — startup fails before the server listens; this screen
  is never rendered.
- **Back button after logout** — the session is gone, so the form renders.

## Open questions

- [ ] None.

## Changelog

| Date | Version | Change |
| --- | --- | --- |
| 2026-11-05 | 1.1.0 | OpenID-only scope, single Claims panel, introductory copy, and indigo visual refresh. |
| 2026-11-05 | 1.0.0 | Initial approved spec for the live demo RP. |
