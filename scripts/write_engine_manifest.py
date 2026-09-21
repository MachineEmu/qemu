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


def series_digests(track: Path) -> list[dict[str, str]]:
    descriptor = tomllib.loads((track / "track.toml").read_text(encoding="utf-8"))
    names = (track / descriptor["patch_series"]).read_text(encoding="utf-8").splitlines()
    patch_root = track / descriptor["patch_root"]
    return [
        {"track": descriptor["id"], "name": name, "sha256": digest(patch_root / name)}
        for name in names
        if name
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--track", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", help="override the track's default target for this bundle")
    args = parser.parse_args()

    descriptor = tomllib.loads((args.track / "track.toml").read_text(encoding="utf-8"))
    targets = [args.target] if args.target else descriptor["targets"]
    # A track applied onto another one, such as the analysis series over the
    # board series, is only reproducible from both: record them in apply order.
    patches = []
    base = descriptor.get("base", {}).get("track")
    if base:
        base_track = args.track.parent / base
        patches += series_digests(base_track)
    patches += series_digests(args.track)
    binary_hash = digest(args.binary)
    inputs = {
        "track_id": descriptor["id"],
        "source_revision": args.source_revision,
        "patches": patches,
        "targets": targets,
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
        "targets": targets,
        "executables": {targets[0]: str(args.binary.relative_to(args.output.parent))},
        "executable_sha256": {targets[0]: binary_hash},
        "qemu_version": version,
        "dirty_source": False,
        "patches_applied": True,
        "status": "complete",
    }
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
