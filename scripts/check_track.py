#!/usr/bin/env python3
"""Check that a track's ordered patch and integration inputs are present."""

from __future__ import annotations

import argparse
from pathlib import Path
import tomllib


def check(track: Path) -> None:
    descriptor = tomllib.loads((track / "track.toml").read_text(encoding="utf-8"))
    patch_root = track / descriptor["patch_root"]
    series = (track / descriptor["patch_series"]).read_text(encoding="utf-8").splitlines()
    if not series or any(not name or name.startswith("#") for name in series):
        raise SystemExit("series must contain non-empty patch names")
    missing = [name for name in series if not (patch_root / name).is_file()]
    if missing:
        raise SystemExit("missing patches: " + ", ".join(missing))
    integration = track.parent.parent / descriptor["integration_root"]
    if not integration.is_dir() or not any(integration.iterdir()):
        raise SystemExit(f"integration root is empty: {integration}")
    print(f"{descriptor['id']}: {len(series)} patches; integration={integration}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("track", type=Path)
    args = parser.parse_args()
    check(args.track)


if __name__ == "__main__":
    main()
