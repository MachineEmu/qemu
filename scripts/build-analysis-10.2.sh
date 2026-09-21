#!/usr/bin/env bash
set -euo pipefail
# The analysis track hides the emulator from the guest; the board track under
# tracks/unifi-10.2 emulates UniFi hardware. They are separate series with
# separate descriptors, but one source tree: the analysis patches link through
# the meson hooks the board series adds, so the board series is applied first.

repo_dir=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
track_dir="$repo_dir/tracks/analysis-10.2"
base_track_dir="$repo_dir/tracks/unifi-10.2"
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

apply_series() {
    local series_dir=$1 patch_name
    while IFS= read -r patch_name; do
        [[ -n "$patch_name" ]] || continue
        local patch="$series_dir/patches/$patch_name"
        [[ -f "$patch" ]] || { echo "missing patch: $patch" >&2; exit 1; }
        git -C "$source_dir" apply "$patch"
    done < "$series_dir/series"
}

apply_series "$base_track_dir"
apply_series "$track_dir"
ln -sfn "$repo_dir/integration/hw/unifi" "$source_dir/hw/unifi"

cargo build -p analysis-profile --release
analysis_header="$repo_dir/crates/analysis-profile/include/analysis_profile.h"
install -Dm644 "$analysis_header" "$source_dir/include/analysis_profile.h"

QEMU_TRACK_DIR="$track_dir" \
QEMU_SOURCE_DIR="$source_dir" \
QEMU_BUILD_DIR="${QEMU_BUILD_DIR:-$repo_dir/.cache/qemu-build-10.2.4-analysis}" \
QEMU_TARGET_LIST=x86_64-softmmu \
QEMU_TARGET_BINARY=qemu-system-x86_64 \
QEMU_ANALYSIS_PROFILE_LIB="$repo_dir/target/release/libanalysis_profile.a" \
"$repo_dir/scripts/build-unifi-10.2.sh" "$@"
