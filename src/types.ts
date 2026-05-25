// Types for the MCP registry server.json manifest (subset of the
// modelcontextprotocol registry schema) and the scanner's output.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface ManifestEnvVar {
  name?: string;
  description?: string;
  isRequired?: boolean;
  isSecret?: boolean;
  format?: string;
}

export interface ManifestPackage {
  registryType?: string; // npm | pypi | oci | nuget | ...
  identifier?: string;
  version?: string;
  transport?: { type?: string; url?: string }; // stdio | http | sse
  environmentVariables?: ManifestEnvVar[];
}

export interface ManifestRemote {
  type?: string; // streamable-http | sse
  url?: string;
  headers?: Array<{ name?: string; isSecret?: boolean }>;
}

export interface Manifest {
  $schema?: string;
  name?: string;
  description?: string;
  version?: string;
  repository?: { url?: string; source?: string };
  packages?: ManifestPackage[];
  remotes?: ManifestRemote[];
  [key: string]: unknown;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  detail: string;
  /** JSON-pointer-ish location of the offending value, when known. */
  path?: string;
}

export interface Report {
  manifestName: string;
  findings: Finding[];
  counts: Record<Severity, number>;
  /** Highest severity present, or "info" when clean. */
  worst: Severity;
  ok: boolean; // true when no finding at or above the configured gate
}

export const SEVERITY_ORDER: Severity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical"
];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}
