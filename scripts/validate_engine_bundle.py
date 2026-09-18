#!/usr/bin/env python3
"""Validate an installed MachineEmu engine bundle manifest and its files."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate(manifest_path: Path) -> dict[str, object]:
    errors: list[str] = []
    try:
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"schema_version": 1, "valid": False, "errors": [str(exc)]}
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        return {"schema_version": 1, "valid": False, "errors": ["manifest schema_version must be 1"]}
    if value.get("status") != "complete":
        errors.append("manifest status must be complete")
    if value.get("dirty_source") is not False:
        errors.append("release bundles must have dirty_source=false")
    if value.get("patches_applied") is not True:
        errors.append("manifest patches_applied must be true")
    targets = value.get("targets")
    executables = value.get("executables")
    hashes = value.get("executable_sha256")
    if not isinstance(targets, list) or not all(isinstance(item, str) for item in targets):
        errors.append("manifest targets must be a list of strings")
        targets = []
    if not isinstance(executables, dict) or not isinstance(hashes, dict):
        errors.append("manifest executable maps are required")
        executables, hashes = {}, {}
    root = manifest_path.parent.resolve()
    for target in targets:
        relative = executables.get(target)
        expected = hashes.get(target)
        if not isinstance(relative, str) or not isinstance(expected, str):
            errors.append(f"missing executable metadata for target: {target}")
            continue
        if not _DIGEST.fullmatch(expected):
            errors.append(f"invalid executable digest for target: {target}")
            continue
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError:
            errors.append(f"executable escapes bundle root: {target}")
            continue
        if path.is_symlink() or not path.is_file():
            errors.append(f"executable is unavailable: {target}")
            continue
        if _sha256(path) != expected:
            errors.append(f"executable digest mismatch: {target}")
    return {
        "schema_version": 1,
        "valid": not errors,
        "errors": errors,
        "manifest": str(manifest_path.resolve()),
        "targets": targets,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args(argv)
    report = validate(args.manifest)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
