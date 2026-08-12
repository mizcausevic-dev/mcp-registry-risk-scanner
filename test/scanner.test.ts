import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { describe, it, expect } from "vitest";

import { scanManifest, scanJson } from "../src/scanner.js";
import { rules } from "../src/rules.js";
import type { Manifest } from "../src/types.js";
import * as api from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): Manifest =>
  JSON.parse(readFileSync(join(here, "..", "fixtures", name), "utf8"));

const ruleIds = (m: Manifest) =>
  new Set(scanManifest(m).findings.map((f) => f.ruleId));

describe("clean manifest", () => {
  const report = scanManifest(fixture("clean.server.json"));

  it("passes the default (high) gate", () => {
    expect(report.ok).toBe(true);
  });

  it("has no high or critical findings", () => {
    expect(report.counts.high).toBe(0);
    expect(report.counts.critical).toBe(0);
  });

  it("does not flag supply-chain or transport rules", () => {
    const ids = ruleIds(fixture("clean.server.json"));
    expect(ids.has("unpinned-package-version")).toBe(false);
    expect(ids.has("insecure-transport")).toBe(false);
    expect(ids.has("missing-repository")).toBe(false);
    expect(ids.has("secret-env-without-description")).toBe(false);
  });
});

describe("hosted remote manifest", () => {
  const m = fixture("xquik.remote.server.json");
  const report = scanManifest(m);
  const ids = ruleIds(m);

  it("flags the remote data-egress and secret-header risks", () => {
    expect(report.ok).toBe(false);
    expect(report.worst).toBe("high");
    expect(ids.has("remote-endpoint")).toBe(true);
    expect(ids.has("remote-secret-header")).toBe(true);
  });

  it("does not flag source, schema, installability, or transport issues", () => {
    expect(ids.has("missing-repository")).toBe(false);
    expect(ids.has("missing-schema")).toBe(false);
    expect(ids.has("no-packages-or-remotes")).toBe(false);
    expect(ids.has("insecure-transport")).toBe(false);
  });

  it("keeps hosted remote findings scoped to one high and one medium", () => {
    expect(report.counts.high).toBe(1);
    expect(report.counts.medium).toBe(1);
    expect(report.counts.low).toBe(0);
    expect(report.counts.info).toBe(0);
  });
});

describe("risky manifest", () => {
  const m = fixture("risky.server.json");
  const report = scanManifest(m);
  const ids = ruleIds(m);

  it("fails the default gate", () => {
    expect(report.ok).toBe(false);
    expect(report.worst).toBe("high");
  });

  it.each([
    "unpinned-package-version",
    "insecure-transport",
    "remote-endpoint",
    "remote-secret-header",
    "excessive-secrets",
    "secret-env-without-description",
    "missing-repository",
    "missing-description",
    "missing-schema",
    "unnamespaced-name"
  ])("flags %s", (id) => {
    expect(ids.has(id)).toBe(true);
  });

  it("sorts findings by descending severity", () => {
    const ranks = report.findings.map((f) => f.severity);
    const firstHigh = ranks.indexOf("high");
    const firstLow = ranks.indexOf("low");
    expect(firstHigh).toBeGreaterThanOrEqual(0);
    if (firstLow >= 0) expect(firstHigh).toBeLessThan(firstLow);
  });

  it("counts findings per severity", () => {
    const total = Object.values(report.counts).reduce((a, b) => a + b, 0);
    expect(total).toBe(report.findings.length);
    expect(report.counts.high).toBeGreaterThanOrEqual(3);
  });
});

describe("gate behaviour", () => {
  it("info gate still passes a truly clean manifest", () => {
    const m: Manifest = {
      $schema: "x",
      name: "ns/ok",
      description: "a sufficiently long description here",
      repository: { url: "https://example.com/r" },
      packages: [
        {
          registryType: "npm",
          identifier: "ok",
          version: "1.0.0",
          transport: { type: "stdio" }
        }
      ]
    };
    expect(scanManifest(m, { gate: "info" }).ok).toBe(true); // truly clean
  });

  it("a single low finding fails an info/low gate but passes high", () => {
    const m: Manifest = {
      $schema: "x",
      name: "ns/ok",
      description: "", // triggers missing-description (low)
      repository: { url: "https://example.com/r" },
      packages: [
        { registryType: "npm", identifier: "ok", version: "1.0.0" }
      ]
    };
    expect(scanManifest(m, { gate: "low" }).ok).toBe(false);
    expect(scanManifest(m, { gate: "high" }).ok).toBe(true);
  });
});

describe("scanJson", () => {
  it("parses and scans raw JSON", () => {
    const raw = readFileSync(
      join(here, "..", "fixtures", "clean.server.json"),
      "utf8"
    );
    expect(scanJson(raw).manifestName).toBe("io.github.example/tidy-server");
  });

  it("throws on invalid JSON", () => {
    expect(() => scanJson("{not json")).toThrow(/Invalid JSON/);
  });

  it("throws on non-object JSON", () => {
    expect(() => scanJson("42")).toThrow(/must be a JSON object/);
  });
});

describe("public API (index barrel)", () => {
  it("re-exports the documented surface", () => {
    expect(typeof api.scanManifest).toBe("function");
    expect(typeof api.scanJson).toBe("function");
    expect(typeof api.severityRank).toBe("function");
    expect(Array.isArray(api.rules)).toBe(true);
    expect(api.SEVERITY_ORDER).toContain("critical");
  });
});

describe("rules registry", () => {
  it("every rule has a stable id and returns an array", () => {
    const empty: Manifest = {};
    const seen = new Set<string>();
    for (const r of rules) {
      expect(r.id).toBeTruthy();
      expect(seen.has(r.id)).toBe(false);
      seen.add(r.id);
      expect(Array.isArray(r.run(empty))).toBe(true);
    }
  });

  it("an empty manifest trips the structural rules", () => {
    const ids = ruleIds({});
    expect(ids.has("no-packages-or-remotes")).toBe(true);
    expect(ids.has("missing-repository")).toBe(true);
    expect(ids.has("missing-schema")).toBe(true);
  });

  it("oci packages are flagged", () => {
    const ids = ruleIds({
      name: "ns/x",
      description: "long enough description here",
      $schema: "x",
      repository: { url: "https://e.com" },
      packages: [{ registryType: "oci", identifier: "img", version: "1.0.0" }]
    });
    expect(ids.has("oci-package")).toBe(true);
  });
});
