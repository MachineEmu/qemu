#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KDIR="${KDIR:-/lib/modules/$(uname -r)/build}"
KERNELRELEASE="${KERNELRELEASE:-}"

if [[ ! -d "$KDIR" ]]; then
  echo "missing kernel build tree: $KDIR" >&2
  echo "install matching kernel headers or set KDIR=/path/to/kernel/build" >&2
  exit 1
fi

make -C "$ROOT/kernel/analysis-kvm" KDIR="$KDIR" check
make -C "$ROOT/kernel/analysis-kvm" KDIR="$KDIR"

if [[ -n "$KERNELRELEASE" ]]; then
  echo "built for kernel release: $KERNELRELEASE"
fi
