# Agent rules

## Hard rule: repository scope

**Never modify files outside this repository without explicit permission.**

This includes remote hosts, production services, databases, DNS, reverse proxies,
systemd units, deployment directories, and user accounts elsewhere. Read-only
inspection is allowed when needed for analysis, but any write, restart, or config
change outside this repository requires the owner's explicit permission first.

Project-specific guidance lives in `_DOCS/AGENTS.md`.
