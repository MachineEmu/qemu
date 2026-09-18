#!/usr/bin/env python3
"""Write provenance for a completed immutable engine build."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--track", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    descriptor = tomllib.loads((args.track / "track.toml").read_text(encoding="utf-8"))
    names = (args.track / descriptor["patch_series"]).read_text(encoding="utf-8").splitlines()
    patches = [{"name": name, "sha256": digest(args.track / descriptor["patch_root"] / name)} for name in names]
    binary_hash = digest(args.binary)
    inputs = {
        "track_id": descriptor["id"],
        "source_revision": args.source_revision,
        "patches": patches,
        "targets": descriptor["targets"],
        "binary_sha256": binary_hash,
    }
    build_digest = hashlib.sha256(
        json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    version = subprocess.run([str(args.binary), "--version"], check=True, capture_output=True, text=True).stdout.strip()
    manifest = {
        "schema_version": 1,
        "track_id": descriptor["id"],
        "build_digest": build_digest,
        "source_revision": args.source_revision,
        "patches": patches,
        "targets": descriptor["targets"],
        "executables": {descriptor["targets"][0]: str(args.binary.relative_to(args.output.parent))},
        "executable_sha256": {descriptor["targets"][0]: binary_hash},
        "qemu_version": version,
        "dirty_source": False,
        "patches_applied": True,
        "status": "complete",
    }
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
