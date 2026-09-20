#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
track_dir="$repo_dir/tracks/unifi-10.2"
source_dir=${QEMU_ANALYSIS_SOURCE_DIR:-"$repo_dir/.cache/qemu-10.2.4-analysis"}
commit=3e0bcba1ca7d6607ca49a988d165f052a3a53323
remote=${QEMU_GIT_URL:-https://gitlab.com/qemu-project/qemu.git}

if [[ ! -d "$source_dir/.git" ]]; then
    git clone "$remote" "$source_dir"
fi
if ! git -C "$source_dir" cat-file -e "$commit^{commit}" 2>/dev/null; then
    git -C "$source_dir" fetch --depth=1 origin "$commit"
fi
git -C "$source_dir" checkout --detach "$commit" >/dev/null
git -C "$source_dir" reset --hard "$commit" >/dev/null
git -C "$source_dir" clean -fd >/dev/null

while IFS= read -r patch_name; do
    [[ -z "$patch_name" ]] || git -C "$source_dir" apply "$track_dir/patches/$patch_name"
done < "$track_dir/series"
for patch in "$track_dir"/analysis-patches/*.patch; do
    [[ -e "$patch" ]] || continue
    git -C "$source_dir" apply "$patch"
done
ln -sfn "$repo_dir/integration/hw/unifi" "$source_dir/hw/unifi"

cargo build -p analysis-profile --release
analysis_header="$repo_dir/crates/analysis-profile/include/analysis_profile.h"
install -Dm644 "$analysis_header" "$source_dir/include/analysis_profile.h"

QEMU_SOURCE_DIR="$source_dir" \
QEMU_TARGET_LIST=x86_64-softmmu \
QEMU_TARGET_BINARY=qemu-system-x86_64 \
QEMU_ANALYSIS_PROFILE_LIB="$repo_dir/target/release/libanalysis_profile.a" \
"$repo_dir/scripts/build-unifi-10.2.sh" "$@"
