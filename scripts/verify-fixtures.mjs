import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { beginCell } = require("@ton/core");

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const binary = resolve(repoRoot, "zig-out/bin/bocdump");

if (!existsSync(binary)) {
  throw new Error("zig-out/bin/bocdump is missing. Run `zig build` first.");
}

function runJson(hex) {
  const out = execFileSync(binary, ["--json", "--hex", hex], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  return JSON.parse(out);
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${expected}, got ${actual}`);
  }
}

function verifyFixture(name, root, opts, expectedCells) {
  const hex = root.toBoc(opts).toString("hex");
  const dump = runJson(hex);

  assertEqual(dump.magic, "0xb5ee9c72", `${name} magic`);
  assertEqual(dump.cells, expectedCells, `${name} cell count`);
  assertEqual(dump.roots.length, 1, `${name} root count`);
  assertEqual(dump.roots[0], 0, `${name} root index`);
  assertEqual(dump.topology_ok, true, `${name} topology`);
  assertEqual(dump.cell_list[0].hash, root.hash().toString("hex"), `${name} root hash`);
  assertEqual(dump.cell_list[0].depth, root.depth(), `${name} root depth`);

  if (opts.crc32) {
    assertEqual(Boolean(dump.crc32c?.ok), true, `${name} CRC32C`);
  } else {
    assertEqual(dump.crc32c, null, `${name} CRC32C absence`);
  }

  if (opts.idx) {
    assertEqual(dump.index.length, expectedCells, `${name} index length`);
  } else {
    assertEqual(dump.index.length, 0, `${name} index absence`);
  }
}

const empty = beginCell().endCell();
verifyFixture("empty crc", empty, { idx: false, crc32: true }, 1);

const leaf = beginCell().storeUint(456, 16).endCell();
const oneRef = beginCell().storeUint(0, 64).storeRef(leaf).endCell();
verifyFixture("one ref", oneRef, { idx: false, crc32: false }, 2);

const indexed = beginCell()
  .storeUint(0b01, 2)
  .storeRef(beginCell().storeUint(0xfe, 8).endCell())
  .endCell();
verifyFixture("indexed crc", indexed, { idx: true, crc32: true }, 2);

console.log("fixture verification ok");
