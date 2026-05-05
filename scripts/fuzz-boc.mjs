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

let seed = 0x6d2b79f5;
function randomByte() {
  seed = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  seed ^= seed + Math.imul(seed ^ (seed >>> 7), 61 | seed);
  return ((seed ^ (seed >>> 14)) >>> 0) & 0xff;
}

function toHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function run(hex, shouldPass = false) {
  try {
    const out = execFileSync(binary, ["--json", "--hex", hex], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 2000,
    });
    JSON.parse(out);
  } catch (error) {
    if (shouldPass) {
      throw error;
    }
    if (error.signal) {
      throw new Error(`process terminated by signal ${error.signal}`);
    }
    const stderr = String(error.stderr ?? "");
    if (stderr.includes("panic") || stderr.includes("thread ")) {
      throw new Error(`unexpected crash output: ${stderr}`);
    }
  }
}

const fixtures = [
  beginCell().endCell(),
  beginCell().storeUint(0, 64).storeRef(beginCell().storeUint(456, 16).endCell()).endCell(),
  beginCell().storeUint(0b01, 2).storeRef(beginCell().storeUint(0xfe, 8).endCell()).endCell(),
];

const validHexes = fixtures.flatMap((cell) => [
  cell.toBoc({ idx: false, crc32: false }).toString("hex"),
  cell.toBoc({ idx: true, crc32: true }).toString("hex"),
]);

for (const hex of validHexes) {
  run(hex, true);
}

for (let i = 0; i < 256; i += 1) {
  const length = randomByte() % 128;
  const bytes = Array.from({ length }, randomByte);
  run(toHex(bytes));
}

for (const hex of validHexes) {
  const original = Buffer.from(hex, "hex");
  for (let i = 0; i < 24; i += 1) {
    const mutated = Buffer.from(original);
    if (mutated.length > 0) {
      mutated[randomByte() % mutated.length] ^= 1 << (randomByte() % 8);
    }
    run(mutated.toString("hex"));
    run(mutated.subarray(0, randomByte() % (mutated.length + 1)).toString("hex"));
  }
}

console.log("fuzz ok");
