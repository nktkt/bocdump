#!/usr/bin/env bash
set -euo pipefail

repo="${REPO:-nktkt/bocdump}"
tag="${RELEASE_TAG:-v0.1.0}"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

case "$(uname -s)" in
  Darwin) os="macos" ;;
  Linux) os="linux" ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  arm64|aarch64) arch="aarch64" ;;
  x86_64|amd64) arch="x86_64" ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

asset="bocdump-${arch}-${os}.tar.gz"
base_url="https://github.com/${repo}/releases/download/${tag}"

curl -fsSLo "${work_dir}/${asset}" "${base_url}/${asset}"
curl -fsSLo "${work_dir}/SHA256SUMS" "${base_url}/SHA256SUMS"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$work_dir" && sha256sum -c SHA256SUMS --ignore-missing)
else
  expected="$(awk -v asset="$asset" '$2 == asset { print $1 }' "${work_dir}/SHA256SUMS")"
  actual="$(shasum -a 256 "${work_dir}/${asset}" | awk '{ print $1 }')"
  test -n "$expected"
  test "$expected" = "$actual"
fi

tar -C "$work_dir" -xzf "${work_dir}/${asset}"
binary="${work_dir}/bocdump-${arch}-${os}/bocdump"
"$binary" --version
"$binary" --json --hex b5ee9c724101010100020000004cacb9cd >/dev/null

echo "release asset smoke test ok: ${asset}"
