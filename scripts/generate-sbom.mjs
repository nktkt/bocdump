import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
const version = packageJson.version;
const created = process.env.SOURCE_DATE_EPOCH
  ? new Date(Number(process.env.SOURCE_DATE_EPOCH) * 1000).toISOString()
  : new Date().toISOString();
const namespaceSuffix = process.env.GITHUB_SHA ?? version;

function checksum(path) {
  const hash = createHash("sha256");
  hash.update(readFileSync(path));
  return hash.digest("hex");
}

const files = [
  "src/main.zig",
  "build.zig",
  "build.zig.zon",
  "README.md",
  "LICENSE",
  "package.json",
  "package-lock.json",
  "scripts/verify-fixtures.mjs",
  "scripts/fuzz-boc.mjs",
  "scripts/generate-sbom.mjs",
  "scripts/smoke-release-asset.sh",
];

const packages = [
  {
    name: "bocdump",
    SPDXID: "SPDXRef-Package-bocdump",
    versionInfo: version,
    downloadLocation: "https://github.com/nktkt/bocdump",
    filesAnalyzed: false,
    licenseConcluded: "MIT",
    licenseDeclared: "MIT",
    copyrightText: "Copyright (c) 2026 naoki-takata",
  },
];

for (const [path, meta] of Object.entries(lock.packages ?? {})) {
  if (path === "" || !path.startsWith("node_modules/")) continue;
  const name = meta.name ?? path.replace("node_modules/", "");
  packages.push({
    name,
    SPDXID: `SPDXRef-Package-${name.replace(/[^A-Za-z0-9.-]/g, "-")}`,
    versionInfo: meta.version ?? "NOASSERTION",
    downloadLocation: meta.resolved ?? "NOASSERTION",
    filesAnalyzed: false,
    licenseConcluded: meta.license ?? "NOASSERTION",
    licenseDeclared: meta.license ?? "NOASSERTION",
    copyrightText: "NOASSERTION",
  });
}

const sbom = {
  spdxVersion: "SPDX-2.3",
  dataLicense: "CC0-1.0",
  SPDXID: "SPDXRef-DOCUMENT",
  name: `bocdump-${version}`,
  documentNamespace: `https://github.com/nktkt/bocdump/sbom/${namespaceSuffix}`,
  creationInfo: {
    created,
    creators: ["Tool: bocdump-sbom-generator"],
  },
  documentDescribes: ["SPDXRef-Package-bocdump"],
  packages,
  files: files.map((path) => ({
    fileName: path,
    SPDXID: `SPDXRef-File-${path.replace(/[^A-Za-z0-9.-]/g, "-")}`,
    checksums: [{ algorithm: "SHA256", checksumValue: checksum(path) }],
    licenseConcluded: path === "LICENSE" ? "MIT" : "NOASSERTION",
    copyrightText: "NOASSERTION",
  })),
  relationships: [
    ...files.map((path) => ({
      spdxElementId: "SPDXRef-Package-bocdump",
      relationshipType: "CONTAINS",
      relatedSpdxElement: `SPDXRef-File-${path.replace(/[^A-Za-z0-9.-]/g, "-")}`,
    })),
    ...packages.slice(1).map((pkg) => ({
      spdxElementId: "SPDXRef-Package-bocdump",
      relationshipType: "DEPENDS_ON",
      relatedSpdxElement: pkg.SPDXID,
    })),
  ],
};

console.log(JSON.stringify(sbom, null, 2));
