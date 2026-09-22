#!/usr/bin/env bash
set -euo pipefail

# Resolve the checkout through git rather than counting directories up from this
# script: the path arithmetic silently produced the wrong root whenever a script
# moved. The fallback covers a non-git export, and `sudo` re-execs, where git
# refuses a checkout owned by another user.
repo_dir=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null) ||
    repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
track_dir="$repo_dir/tracks/unifi-10.2"
source_dir=${QEMU_SOURCE_DIR:-"$repo_dir/.cache/qemu-10.2.4-unifi"}
commit=3e0bcba1ca7d6607ca49a988d165f052a3a53323
remote=${QEMU_GIT_URL:-https://gitlab.com/qemu-project/qemu.git}

if [[ ! -d "$source_dir/.git" ]]; then
    mkdir -p "$(dirname "$source_dir")"
    git clone "$remote" "$source_dir"
fi
if ! git -C "$source_dir" cat-file -e "$commit^{commit}" 2>/dev/null; then
    git -C "$source_dir" fetch --depth=1 origin "$commit"
fi
git -C "$source_dir" checkout --detach "$commit" >/dev/null
# This checkout is a generated input, not a development worktree. Clean it
# before applying the repository-owned patch series so stale edits from the
# former /tmp integration cannot make a reproducible fetch order-dependent.
git -C "$source_dir" reset --hard "$commit" >/dev/null
git -C "$source_dir" clean -fd >/dev/null
actual=$(git -C "$source_dir" rev-parse HEAD)
[[ "$actual" == "$commit" ]] || { echo "QEMU checkout is $actual, expected $commit" >&2; exit 1; }

while IFS= read -r patch_name; do
    [[ -n "$patch_name" ]] || continue
    patch="$track_dir/patches/$patch_name"
    [[ -f "$patch" ]] || { echo "missing track patch: $patch" >&2; exit 1; }
    [[ -e "$patch" ]] || continue
    if git -C "$source_dir" apply --check "$patch" >/dev/null 2>&1; then
        git -C "$source_dir" apply "$patch"
    elif ! git -C "$source_dir" apply --check --reverse "$patch" >/dev/null 2>&1; then
        echo "patch does not apply: $patch" >&2; exit 1
    fi
done < "$track_dir/series"
ln -sfn "$repo_dir/integration/hw/unifi" "$source_dir/hw/unifi"
echo "$source_dir"
