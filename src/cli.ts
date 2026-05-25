#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

import { scanJson } from "./scanner.js";
import { type Report, type Severity, SEVERITY_ORDER } from "./types.js";

interface Args {
  source?: string;
  json: boolean;
  gate: Severity;
  help: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { json: false, gate: "high", help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") args.json = true;
    else if (a === "-h" || a === "--help") args.help = true;
    else if (a === "--gate") {
      const v = argv[++i] as Severity;
      if (!SEVERITY_ORDER.includes(v)) {
        throw new Error(
          `--gate must be one of: ${SEVERITY_ORDER.join(", ")}`
        );
      }
      args.gate = v;
    } else if (!a.startsWith("-")) args.source = a;
    else throw new Error(`Unknown option: ${a}`);
  }
  return args;
}

async function loadManifest(source: string): Promise<string> {
  if (/^https?:\/\//.test(source)) {
    const res = await fetch(source);
    if (!res.ok) {
      throw new Error(`Fetch failed: ${res.status} ${res.statusText}`);
    }
    return await res.text();
  }
  return readFileSync(source, "utf8");
}

const COLOR: Record<Severity, string> = {
  critical: "\x1b[41m\x1b[37m",
  high: "\x1b[31m",
  medium: "\x1b[33m",
  low: "\x1b[36m",
  info: "\x1b[90m"
};
const RESET = "\x1b[0m";

function render(report: Report, useColor: boolean): string {
  const tag = (s: Severity) =>
    useColor ? `${COLOR[s]}${s.toUpperCase()}${RESET}` : s.toUpperCase();
  const lines: string[] = [];
  lines.push(`MCP manifest: ${report.manifestName}`);
  if (report.findings.length === 0) {
    lines.push("  no findings — clean");
  }
  for (const f of report.findings) {
    lines.push(`  [${tag(f.severity)}] ${f.ruleId}: ${f.title}`);
    lines.push(`      ${f.detail}`);
    if (f.path) lines.push(`      at ${f.path}`);
  }
  const summary = SEVERITY_ORDER.slice()
    .reverse()
    .map((s) => `${report.counts[s]} ${s}`)
    .join(", ");
  lines.push(`Summary: ${summary}`);
  lines.push(`Worst: ${report.worst} — ${report.ok ? "PASS" : "FAIL"}`);
  return lines.join("\n");
}

const HELP = `mcp-registry-risk-scanner — flag security risks in an MCP server.json manifest

Usage:
  mcp-risk-scan <path-or-url> [--gate <severity>] [--json]

Options:
  --gate <severity>   Fail (exit 1) if any finding is at or above this level.
                      One of: info, low, medium, high, critical. Default: high.
  --json              Emit the full report as JSON.
  -h, --help          Show this help.

Exit codes: 0 = pass, 1 = findings at/above gate, 2 = usage/IO error.`;

export async function main(argv: string[]): Promise<number> {
  let args: Args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n`);
    return 2;
  }
  if (args.help || !args.source) {
    process.stdout.write(`${HELP}\n`);
    return args.help ? 0 : 2;
  }
  let report: Report;
  try {
    const raw = await loadManifest(args.source);
    report = scanJson(raw, { gate: args.gate });
  } catch (e) {
    process.stderr.write(`error: ${(e as Error).message}\n`);
    return 2;
  }
  if (args.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    const useColor = process.stdout.isTTY === true && !process.env.NO_COLOR;
    process.stdout.write(`${render(report, useColor)}\n`);
  }
  return report.ok ? 0 : 1;
}

const invokedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      process.stderr.write(`fatal: ${(e as Error).message}\n`);
      process.exit(2);
    }
  );
}
