# Security Policy

`mcp-registry-risk-scanner` performs **static analysis only** — it reads an MCP
`server.json` manifest and reports risk signals. It never installs, executes, or
connects to the scanned server, and it makes no network calls except to fetch a
manifest from an explicit `https?://` argument you pass on the command line.

## Supported versions

Only the latest tagged release is supported.

## Reporting a vulnerability

Please use GitHub Security Advisories for private disclosure:

- [Open a security advisory](https://github.com/mizcausevic-dev/mcp-registry-risk-scanner/security/advisories/new)

Do not file public issues for security reports.
