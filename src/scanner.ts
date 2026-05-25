import { rules } from "./rules.js";
import {
  type Finding,
  type Manifest,
  type Report,
  type Severity,
  SEVERITY_ORDER,
  severityRank
} from "./types.js";

export interface ScanOptions {
  /** Findings at or above this severity make the report `ok: false`. Default: "high". */
  gate?: Severity;
}

const emptyCounts = (): Record<Severity, number> => ({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0
});

export function scanManifest(
  manifest: Manifest,
  opts: ScanOptions = {}
): Report {
  const gate = opts.gate ?? "high";
  const findings: Finding[] = rules
    .flatMap((r) => r.run(manifest))
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  const counts = emptyCounts();
  for (const f of findings) counts[f.severity]++;

  const worst: Severity =
    [...SEVERITY_ORDER].reverse().find((s) => counts[s] > 0) ?? "info";

  // A manifest passes when no finding is at or above the gate.
  // (An empty findings list always passes — `every` over [] is true.)
  const ok = findings.every(
    (f) => severityRank(f.severity) < severityRank(gate)
  );
  return {
    manifestName: manifest.name ?? "(unnamed)",
    findings,
    counts,
    worst,
    ok
  };
}

/** Parse + scan a raw JSON string. Throws on invalid JSON. */
export function scanJson(raw: string, opts: ScanOptions = {}): Report {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    throw new Error(
      `Invalid JSON manifest: ${(e as Error).message}`
    );
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("Manifest must be a JSON object.");
  }
  return scanManifest(parsed as Manifest, opts);
}
