# bocdump

`bocdump` is a Zig CLI for inspecting and validating TON Bag-of-Cells (BoC)
payloads.

It is designed as a low-level developer tool: it dumps BoC headers, serialized
cell records, references, computed hashes, computed depths, CRC32C status, and
basic exotic cell metadata.

## Features

- Reads BoC input from hex, base64, files, or stdin
- Supports text output and machine-readable JSON output
- Parses BoC magic values `b5ee9c72`, `68ff65f3`, and `acc3a728`
- Validates root bounds, reference bounds, index offsets, topological order, and
  optional CRC32C checksums
- Recomputes ordinary cell representation hashes and depths
- Performs basic validation for pruned branch, library reference, Merkle proof,
  and Merkle update exotic cells

## Usage

```sh
zig build
zig build run -- --version
zig build run -- --hex b5ee9c724101010100020000004cacb9cd
zig build run -- --json --file contract.boc
zig-out/bin/bocdump --base64 '<base64-boc>'
```

Inputs:

- `--hex <hex>`
- `--base64 <base64>`
- `--file <path>`
- `<path>`
- `--file -` for stdin

Outputs:

- Text dump by default
- JSON with `--json`
- Version with `--version`

Example:

```sh
zig build run -- --json --hex b5ee9c724101010100020000004cacb9cd
```

## Validation

The parser validates:

- BoC magic values `b5ee9c72`, `68ff65f3`, and `acc3a728`
- header integer widths, root bounds, reference bounds, and topological order
- optional CRC32C checksums
- index table offsets when present
- cell bit descriptors and padded bitstrings
- ordinary cell level masks
- ordinary cell representation hash and depth
- basic exotic cell type, size, reference, hash, and depth invariants for
  pruned branch, library reference, Merkle proof, and Merkle update cells

This is a low-level BoC/Cell inspector. It does not decode arbitrary TL-B
schemas into high-level contract/message objects.

## Requirements

- Zig 0.15.2 or newer

## Verification

Run:

```sh
zig fmt --check build.zig src/main.zig
zig build test
zig build -Doptimize=ReleaseSafe
npm ci
npm run verify:fixtures
```

The tests include CRC32C, ordinary cell hashes/depths, indexed BoC offsets,
CRC failure rejection, non-canonical reference rejection, and CLI option
parsing.

The fixture verifier generates BoCs with `@ton/core`, runs `bocdump --json`,
and compares root hashes, depths, CRC status, and indexed output shape.

## Status

This project is intended for developer inspection and validation workflows. It
is not a replacement for a full TON SDK, a TL-B decoder, or a third-party
security audit.

## License

MIT
