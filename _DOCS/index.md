# Screen registry

Every screen in the demo RP is listed here. Agents read this file first. Add a
row in the same change that adds a screen doc.

| ID | Title | Route | Status | File |
| --- | --- | --- | --- | --- |
| `screen-demo-home` | Demo RP home / launch | `/` | `approved` | [screens/home.screen.md](screens/home.screen.md) |
| `screen-account-dashboard` | Account dashboard | `/account` | `approved` | [screens/account-dashboard.screen.md](screens/account-dashboard.screen.md) |
| `screen-escalation-request` | Escalation request | `/escalate` | `review` | [screens/escalation-request.screen.md](screens/escalation-request.screen.md) |
| `screen-flow-result` | Flow result | `/result` | `approved` | [screens/flow-result.screen.md](screens/flow-result.screen.md) |
| `screen-auth-preview` | Authorization request preview | `/start?preview=1` | `approved` | [screens/auth-preview.screen.md](screens/auth-preview.screen.md) |
| `screen-session-ended` | Session ended by TrustNet | `/account` (stale cookie) | `approved` | [screens/session-ended.screen.md](screens/session-ended.screen.md) |
| `screen-account-erased` | Account data erased | `/account` (stale cookie) | `approved` | [screens/account-erased.screen.md](screens/account-erased.screen.md) |
| `screen-webhook-log` | Webhook deliveries | `/webhooks` | `approved` | [screens/webhook-log.screen.md](screens/webhook-log.screen.md) |
| `screen-error` | Error | any failing route | `approved` | [screens/error.screen.md](screens/error.screen.md) |

## Status meanings

| Status | Implement against it? |
| --- | --- |
| `draft` | No — design not settled, ask first |
| `review` | Only with confirmation |
| `approved` | Yes |
| `deprecated` | No — ignore, kept for history |

## Machine-readable surfaces

These are JSON, not screens, and are documented here only so they are not
mistaken for missing screens:

| Route | Purpose |
| --- | --- |
| `/debug/state` | Sessions, flows, and the last logout token |
| `/debug/purge` | Verified and failed purge deliveries |
| `/debug/reset` | Drop accumulated demo state |
| `/healthz` | Liveness |
