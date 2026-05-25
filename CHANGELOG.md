# Changelog

## v0.1.0 — 2026-05-25

- Initial release: static security scanner for MCP `server.json` registry manifests.
- 12 rules across supply-chain (unpinned versions, OCI), transport (plaintext HTTP), credentials (excessive/undocumented secrets, secret headers to remotes), data-egress (remote endpoints), and provenance (missing repository/schema/description, unnamespaced name).
- Library API (`scanManifest`, `scanJson`) + CLI (`mcp-risk-scan`) with severity gating and JSON output; exit codes for CI gating.
- Node 20/22 CI (lint, typecheck, 100% statement coverage, build, demo, `npm audit`), AGPL-3.0-or-later, Dependabot.
