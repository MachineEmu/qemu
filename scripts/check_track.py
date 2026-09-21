#!/usr/bin/env python3
"""Check that a track's ordered patch and integration inputs are present."""

from __future__ import annotations

import argparse
from pathlib import Path
import tomllib


def read_series(track: Path, descriptor: dict) -> list[str]:
    series = (track / descriptor["patch_series"]).read_text(encoding="utf-8").splitlines()
    if not series or any(not name or name.startswith("#") for name in series):
        raise SystemExit(f"{track}: series must contain non-empty patch names")
    patch_root = track / descriptor["patch_root"]
    missing = [name for name in series if not (patch_root / name).is_file()]
    if missing:
        raise SystemExit(f"{track}: missing patches: " + ", ".join(missing))
    return series


def load(track: Path) -> dict:
    return tomllib.loads((track / "track.toml").read_text(encoding="utf-8"))


def check(track: Path) -> None:
    descriptor = load(track)
    series = read_series(track, descriptor)
    # A track that only modifies an existing build, such as the analysis series
    # over the board series, declares the track whose patches it applies onto.
    base = descriptor.get("base", {}).get("track")
    if base:
        base_track = track.parent / base
        base_descriptor = load(base_track)
        base_series = read_series(base_track, base_descriptor)
        if base_descriptor["source"]["revision"] != descriptor["source"]["revision"]:
            raise SystemExit(f"{descriptor['id']}: base {base} pins another source revision")
        print(f"{descriptor['id']}: base {base} contributes {len(base_series)} patches")
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
