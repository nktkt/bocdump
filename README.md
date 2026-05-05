# bocdump

[![CI](https://github.com/nktkt/bocdump/actions/workflows/ci.yml/badge.svg)](https://github.com/nktkt/bocdump/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/nktkt/bocdump)](https://github.com/nktkt/bocdump/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-0.15.2-f7a41d.svg)](https://ziglang.org/)

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

## Install

Download a release asset for your platform:

```sh
curl -LO https://github.com/nktkt/bocdump/releases/download/v0.1.1/bocdump-aarch64-macos.tar.gz
curl -LO https://github.com/nktkt/bocdump/releases/download/v0.1.1/SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing
tar -xzf bocdump-aarch64-macos.tar.gz
./bocdump-aarch64-macos/bocdump --version
```

Available release assets:

- `bocdump-x86_64-linux.tar.gz`
- `bocdump-aarch64-linux.tar.gz`
- `bocdump-x86_64-macos.tar.gz`
- `bocdump-aarch64-macos.tar.gz`

Or build from source:

```sh
git clone https://github.com/nktkt/bocdump.git
cd bocdump
zig build -Doptimize=ReleaseSafe
zig-out/bin/bocdump --version
```

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
npm run fuzz
npm run smoke:release
```

The tests include CRC32C, ordinary cell hashes/depths, indexed BoC offsets,
CRC failure rejection, non-canonical reference rejection, and CLI option
parsing.

The fixture verifier generates BoCs with `@ton/core`, runs `bocdump --json`,
and compares root hashes, depths, CRC status, and indexed output shape.

The release smoke test downloads the current platform asset, verifies it
against `SHA256SUMS`, extracts it, and runs `bocdump --version` plus a sample
BoC dump.

Release builds also publish `SHA256SUMS`, `bocdump.spdx.json`, and GitHub
artifact attestations for release assets.

## Status

This project is intended for developer inspection and validation workflows. It
is not a replacement for a full TON SDK, a TL-B decoder, or a third-party
security audit.

## License

MIT
