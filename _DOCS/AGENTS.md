# Agent instructions

This directory specifies the intended behaviour of the demo relying party. Read
it before changing a user-facing flow or a stateful entity.

## Reading order

1. `index.md` — the screen registry. Find the screen that covers your task.
2. The screen's frontmatter — check `status`. `draft` means the design is not
   settled; ask before implementing against it. `deprecated` means ignore it.
3. The screen's **Purpose** section — confirm relevance in one read.
4. The **Layout / Copy / Actions / Navigation outcomes** tables — this is the
   authoritative content. Prefer it over the rendering in `_DESIGN`.
5. `related` in frontmatter — follow to connected screens before concluding you
   have the full picture.

## Ground rules

- **Hard rule: never modify files outside this repository without explicit
  permission.** This includes remote hosts, production services, databases, DNS,
  reverse proxies, systemd units, deployment directories, and user accounts
  elsewhere. Read-only inspection is allowed for analysis; any write, restart,
  or config change outside this repository requires the owner's explicit
  permission first.
- **Screen docs are the source of truth for intent, not the current code.** If
  the code and a doc disagree, say so explicitly instead of silently choosing
  one.
- **Never invent screens, states, or actions.** If a task needs something absent
  from a screen doc, stop and flag the gap. An unlisted screen is a design
  question, not an implementation detail.
- **Keep the rendering and the doc in sync.** A changed screen updates its
  `_DOCS/screens/*.md` and its `_DESIGN/screens/*.html` in the same change.
- **When editing a screen doc:** update the body, `version`, `updated`, and the
  *Changelog* row together. Partial edits break the contract.
- **When adding a screen doc:** copy `_DESIGN`'s screen shell, add a row to
  `index.md`, and add the matching `_DESIGN` page in the same change.

## Workflow (binding)

This project follows the TrustNet plan-first cycle, adapted for a single small
binary:

1. Plan in `plan.md`, refine with the owner, and do not write code until the
   plan is approved.
2. Implement one part at a time. After each part: update `plan.md`, note what
   actually landed, and **stop for the owner's confirmation** before the next
   part.
3. If reality forces a deviation, stop and renegotiate the plan first.

## Invariants

- Never log tokens, cookies, authorization codes, or claim values. Claim names
  only.
- The RP only sees the PPID in `sub`; never store or display an `account_id` or
  `persona_id`.
- Store the minimum needed for the demo, always with a one-hour TTL.
- The HTML redacts token values; `/debug/state` is the only surface that exposes
  them, exactly as the inspector already does.
