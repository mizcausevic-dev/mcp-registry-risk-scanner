import type { Finding, Manifest, ManifestPackage } from "./types.js";

export interface Rule {
  id: string;
  run(m: Manifest): Finding[];
}

const isHttpish = (t?: string) =>
  t === "http" || t === "sse" || t === "streamable-http";

const versionLooksPinned = (v?: string): boolean => {
  if (!v) return false;
  if (/^(latest|next|\*)$/i.test(v)) return false;
  if (/^[\^~><=]|\s-\s|x/i.test(v)) return false; // ranges / wildcards
  return /^\d+\.\d+\.\d+/.test(v);
};

const eachPackage = (m: Manifest): Array<[number, ManifestPackage]> =>
  (m.packages ?? []).map((p, i) => [i, p]);

export const rules: Rule[] = [
  {
    id: "missing-repository",
    run: (m) =>
      m.repository?.url
        ? []
        : [
            {
              ruleId: "missing-repository",
              severity: "medium",
              title: "No source repository declared",
              detail:
                "The manifest has no repository.url, so consumers cannot audit the source behind the published package.",
              path: "/repository/url"
            }
          ]
  },
  {
    id: "missing-description",
    run: (m) => {
      const d = (m.description ?? "").trim();
      if (d.length >= 16) return [];
      return [
        {
          ruleId: "missing-description",
          severity: "low",
          title: "Missing or thin description",
          detail:
            "A short/empty description makes the server's purpose and tool surface opaque to reviewers.",
          path: "/description"
        }
      ];
    }
  },
  {
    id: "missing-schema",
    run: (m) =>
      m.$schema
        ? []
        : [
            {
              ruleId: "missing-schema",
              severity: "info",
              title: "No $schema pinned",
              detail:
                "Without a $schema the manifest cannot be validated against a known registry schema version.",
              path: "/$schema"
            }
          ]
  },
  {
    id: "no-packages-or-remotes",
    run: (m) =>
      (m.packages?.length ?? 0) === 0 && (m.remotes?.length ?? 0) === 0
        ? [
            {
              ruleId: "no-packages-or-remotes",
              severity: "medium",
              title: "No installable packages or remotes",
              detail:
                "The manifest declares neither a package nor a remote, so there is nothing to install or connect to.",
              path: "/packages"
            }
          ]
        : []
  },
  {
    id: "unpinned-package-version",
    run: (m) =>
      eachPackage(m)
        .filter(([, p]) => !versionLooksPinned(p.version))
        .map(([i, p]) => ({
          ruleId: "unpinned-package-version",
          severity: "high" as const,
          title: "Package version not pinned",
          detail: `Package "${p.identifier ?? "?"}" version "${
            p.version ?? "(none)"
          }" is missing or a floating range — supply-chain risk: an attacker-controlled later version can be pulled.`,
          path: `/packages/${i}/version`
        }))
  },
  {
    id: "insecure-transport",
    run: (m) => {
      const out: Finding[] = [];
      eachPackage(m).forEach(([i, p]) => {
        const url = p.transport?.url;
        if (url && url.startsWith("http://")) {
          out.push({
            ruleId: "insecure-transport",
            severity: "high",
            title: "Transport over plaintext HTTP",
            detail: `Package transport URL "${url}" uses http:// — traffic (incl. tool args) is unencrypted and tamperable.`,
            path: `/packages/${i}/transport/url`
          });
        }
      });
      (m.remotes ?? []).forEach((r, i) => {
        if (r.url && r.url.startsWith("http://")) {
          out.push({
            ruleId: "insecure-transport",
            severity: "high",
            title: "Remote over plaintext HTTP",
            detail: `Remote URL "${r.url}" uses http:// — credentials in headers and tool data travel in cleartext.`,
            path: `/remotes/${i}/url`
          });
        }
      });
      return out;
    }
  },
  {
    id: "remote-endpoint",
    run: (m) =>
      (m.remotes ?? [])
        .filter((r) => isHttpish(r.type) || r.url)
        .map((r, i) => ({
          ruleId: "remote-endpoint",
          severity: "medium" as const,
          title: "Network-exposed remote endpoint",
          detail: `Remote "${
            r.url ?? r.type ?? "?"
          }" means tool calls and their data leave the client to a third-party host — confirm data-egress is acceptable.`,
          path: `/remotes/${i}`
        }))
  },
  {
    id: "remote-secret-header",
    run: (m) => {
      const out: Finding[] = [];
      (m.remotes ?? []).forEach((r, ri) => {
        (r.headers ?? []).forEach((h, hi) => {
          if (h.isSecret) {
            out.push({
              ruleId: "remote-secret-header",
              severity: "high",
              title: "Secret sent to remote in a header",
              detail: `Header "${
                h.name ?? "?"
              }" is a secret transmitted to a remote endpoint — a leak or rogue host exposes the credential.`,
              path: `/remotes/${ri}/headers/${hi}`
            });
          }
        });
      });
      return out;
    }
  },
  {
    id: "secret-env-without-description",
    run: (m) => {
      const out: Finding[] = [];
      eachPackage(m).forEach(([pi, p]) => {
        (p.environmentVariables ?? []).forEach((e, ei) => {
          if (e.isSecret && !(e.description ?? "").trim()) {
            out.push({
              ruleId: "secret-env-without-description",
              severity: "medium",
              title: "Secret env var lacks description",
              detail: `Secret "${
                e.name ?? "?"
              }" has no description, so reviewers can't tell what credential it grants or its blast radius.`,
              path: `/packages/${pi}/environmentVariables/${ei}`
            });
          }
        });
      });
      return out;
    }
  },
  {
    id: "excessive-secrets",
    run: (m) => {
      const out: Finding[] = [];
      eachPackage(m).forEach(([pi, p]) => {
        const secrets = (p.environmentVariables ?? []).filter(
          (e) => e.isSecret
        );
        if (secrets.length >= 4) {
          out.push({
            ruleId: "excessive-secrets",
            severity: "medium",
            title: "Broad credential footprint",
            detail: `Package "${
              p.identifier ?? "?"
            }" requests ${secrets.length} secret env vars — a single compromise grants wide access; consider scoping or a broker.`,
            path: `/packages/${pi}/environmentVariables`
          });
        }
      });
      return out;
    }
  },
  {
    id: "oci-package",
    run: (m) =>
      eachPackage(m)
        .filter(([, p]) => (p.registryType ?? "").toLowerCase() === "oci")
        .map(([i, p]) => ({
          ruleId: "oci-package",
          severity: "low" as const,
          title: "Container (OCI) package",
          detail: `Package "${
            p.identifier ?? "?"
          }" ships as an OCI image — verify the image is from a trusted registry and digest-pinned.`,
          path: `/packages/${i}/registryType`
        }))
  },
  {
    id: "unnamespaced-name",
    run: (m) => {
      const n = m.name ?? "";
      // Registry convention: reverse-DNS namespace e.g. io.github.user/server
      if (/^[a-z0-9.-]+\/[A-Za-z0-9_.-]+$/.test(n)) return [];
      return [
        {
          ruleId: "unnamespaced-name",
          severity: "info",
          title: "Name not in namespaced form",
          detail: `Name "${
            n || "(none)"
          }" is not in the reverse-DNS "namespace/server" form, which weakens name-squatting protection.`,
          path: "/name"
        }
      ];
    }
  }
];
