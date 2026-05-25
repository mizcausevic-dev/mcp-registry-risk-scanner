# mcp-registry-risk-scanner

Security scanner for **Model Context Protocol (MCP)** `server.json` registry manifests. It flags supply-chain, transport, credential, and data-egress risks **before** you install a server or list it in a registry — a pre-flight check for the MCP supply chain.

Part of the [Kinetic Gain](https://suite.kineticgain.com) MCP governance lane (alongside [`mcp-kinetic-gain`](https://github.com/mizcausevic-dev/mcp-kinetic-gain) and the [MCP Tool Cards](https://toolcards.kineticgain.com) spec).

## Why

The MCP registry format lets a server declare its packages, transports, remotes, and the secrets it wants. Those declarations are exactly where risk hides: a floating package version (supply-chain), a plaintext `http://` transport (interception), a pile of secret env vars (blast radius), or a remote endpoint that quietly ships your tool calls to a third party (data egress). This scanner reads a manifest and reports those signals with a severity and a JSON-pointer location, so a human or a CI gate can decide before anything runs.

It reads but never executes the server — analysis is purely static over the manifest.

## Install

```bash
npm install -g mcp-registry-risk-scanner   # CLI
# or as a library:
npm install mcp-registry-risk-scanner
```

Requires Node ≥ 20.

## CLI

```bash
mcp-risk-scan ./server.json                 # scan a local manifest
mcp-risk-scan https://example.com/server.json   # scan a remote manifest
mcp-risk-scan ./server.json --gate medium   # fail on medium+ findings
mcp-risk-scan ./server.json --json          # machine-readable report
```

Exit codes: `0` pass · `1` findings at or above the gate · `2` usage/IO error. Default gate is `high`, so the scanner fails CI only on high/critical risks unless you tighten it.

### CI gate example

```yaml
- run: npx mcp-registry-risk-scanner ./server.json --gate high
```

## Library

```ts
import { scanManifest, scanJson } from "mcp-registry-risk-scanner";

const report = scanJson(await fetch(url).then((r) => r.text()), { gate: "medium" });
if (!report.ok) {
  for (const f of report.findings) console.log(f.severity, f.ruleId, f.path);
}
```

`scanManifest(manifest, { gate })` returns a `Report` with `findings`, per-severity `counts`, the `worst` severity, and `ok` (true when nothing reaches the gate).

## Rules

| Rule | Severity | Flags |
|---|---|---|
| `unpinned-package-version` | high | package version missing / `latest` / a floating range |
| `insecure-transport` | high | package or remote transport over plaintext `http://` |
| `remote-secret-header` | high | a secret sent to a remote endpoint in a header |
| `remote-endpoint` | medium | a network-exposed remote (tool data leaves the client) |
| `excessive-secrets` | medium | a package requesting many secret env vars (blast radius) |
| `secret-env-without-description` | medium | a secret env var with no description |
| `missing-repository` | medium | no `repository.url` to audit the source |
| `no-packages-or-remotes` | medium | nothing installable or connectable declared |
| `oci-package` | low | ships as an OCI image — verify registry + digest |
| `missing-description` | low | empty/thin description |
| `missing-schema` | info | no `$schema` pinned for validation |
| `unnamespaced-name` | info | name not in reverse-DNS `namespace/server` form |

Severities, in order: `info < low < medium < high < critical`.

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE).
