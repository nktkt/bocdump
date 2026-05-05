import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { Address, beginCell, external, storeMessage } = require("@ton/core");

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const binary = resolve(repoRoot, "zig-out/bin/bocdump");

if (!existsSync(binary)) {
  throw new Error("zig-out/bin/bocdump is missing. Run `zig build` first.");
}

function runJson(hex, extraArgs = []) {
  const out = execFileSync(binary, ["--json", ...extraArgs, "--hex", hex], {
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

function verifyExternalMessage() {
  const destHash = "11".repeat(32);
  const dest = Address.parseRaw(`0:${destHash}`);
  const root = beginCell().store(storeMessage(external({ to: dest }))).endCell();
  const dump = runJson(root.toBoc({ idx: false, crc32: false }).toString("hex"), [
    "--decode",
    "message",
  ]);
  const decoded = dump.decode.message;

  assertEqual(dump.decode.kind, "message", "external message decode kind");
  assertEqual(decoded.info.type, "external-in", "external message info type");
  assertEqual(decoded.info.src.type, "none", "external message source");
  assertEqual(decoded.info.dest.type, "internal", "external message dest type");
  assertEqual(decoded.info.dest.workchain, 0, "external message dest workchain");
  assertEqual(decoded.info.dest.hash, destHash, "external message dest hash");
  assertEqual(decoded.info.import_fee, "0", "external message import fee");
  assertEqual(decoded.init, null, "external message init");
  assertEqual(decoded.body.storage, "inline", "external message body storage");
  assertEqual(decoded.body.bits, 0, "external message body bits");
}

function verifyInternalMessage() {
  const srcHash = "22".repeat(32);
  const destHash = "33".repeat(32);
  const src = Address.parseRaw(`0:${srcHash}`);
  const dest = Address.parseRaw(`-1:${destHash}`);
  const body = beginCell().storeUint(0xabcdef01, 32).endCell();
  const root = beginCell()
    .store(
      storeMessage({
        info: {
          type: "internal",
          ihrDisabled: true,
          bounce: true,
          bounced: false,
          src,
          dest,
          value: { coins: 123456789n },
          ihrFee: 0n,
          forwardFee: 0n,
          createdLt: 42n,
          createdAt: 7,
        },
        init: null,
        body,
      }),
    )
    .endCell();
  const dump = runJson(root.toBoc({ idx: false, crc32: false }).toString("hex"), [
    "--decode",
    "message",
  ]);
  const info = dump.decode.message.info;

  assertEqual(info.type, "internal", "internal message info type");
  assertEqual(info.ihr_disabled, true, "internal message ihr disabled");
  assertEqual(info.bounce, true, "internal message bounce");
  assertEqual(info.bounced, false, "internal message bounced");
  assertEqual(info.src.hash, srcHash, "internal message source hash");
  assertEqual(info.dest.workchain, -1, "internal message dest workchain");
  assertEqual(info.dest.hash, destHash, "internal message dest hash");
  assertEqual(info.value.coins, "123456789", "internal message coins");
  assertEqual(info.value.extra_currencies.present, false, "internal message extra currencies");
  assertEqual(info.ihr_fee, "0", "internal message ihr fee");
  assertEqual(info.forward_fee, "0", "internal message forward fee");
  assertEqual(info.created_lt, "42", "internal message created lt");
  assertEqual(info.created_at, 7, "internal message created at");
  assertEqual(dump.decode.message.body.storage, "inline", "internal message body storage");
  assertEqual(dump.decode.message.body.bits, 32, "internal message body bits");
}

verifyExternalMessage();
verifyInternalMessage();

console.log("fixture verification ok");
