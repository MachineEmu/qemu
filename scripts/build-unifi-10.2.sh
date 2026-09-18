#!/usr/bin/env bash
set -euo pipefail
# Resolve the checkout through git rather than counting directories up from this
# script: the path arithmetic silently produced the wrong root whenever a script
# moved. The fallback covers a non-git export, and `sudo` re-execs, where git
# refuses a checkout owned by another user.
repo_dir=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null) ||
    repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
track_dir="$repo_dir/tracks/unifi-10.2"
source_dir=${QEMU_SOURCE_DIR:-"$repo_dir/.cache/qemu-10.2.4"}
build_dir=${QEMU_BUILD_DIR:-"$repo_dir/.cache/qemu-build-10.2.4"}
target_list=${QEMU_TARGET_LIST:-aarch64-softmmu}
target_binary=${QEMU_TARGET_BINARY:-qemu-system-aarch64}

ensure_u2f_header() {
    local qemu_source=$1
    local include_dir header
    include_dir=$(pkg-config --variable=includedir u2f-emu 2>/dev/null || true)
    if [[ -n "$include_dir" && -f "$include_dir/u2f-emu.h" ]]; then
        header="$include_dir/u2f-emu.h"
    else
        header=$(find /nix/store -path '*/include/u2f-emu.h' -print -quit 2>/dev/null || true)
    fi
    if [[ -n "${header:-}" ]]; then
        mkdir -p "$qemu_source/include/u2f-emu"
        ln -sfn "$header" "$qemu_source/include/u2f-emu/u2f-emu.h"
    fi
}

# fetch.sh owns the QEMU checkout: it clones the pinned commit, applies
# qemu/patches and links in qemu/hw/unifi. Without it `cd` below failed with a
# bare "No such file or directory" that named the cache path but not the cause.
if [[ ! -d "$source_dir" ]]; then
    echo "no QEMU source at $source_dir" >&2
    echo "run scripts/fetch.sh first, or 'task qemu:build' which does both" >&2
    exit 1
fi
source_dir=$(cd "$source_dir" && pwd)
source_revision=$(git -C "$source_dir" rev-parse HEAD)
build_dir=$(mkdir -p "$build_dir" && cd "$build_dir" && pwd)
ensure_u2f_header "$source_dir"
cargo build -p board-ffi --release
# Copy the generated header only when its contents change. An unconditional
# `install` bumps the mtime on every run, and every QEMU object that includes
# it would be recompiled even though nothing about the board ABI moved.
board_header="$repo_dir/crates/board-ffi/include/unifi_board.h"
if ! cmp -s "$board_header" "$source_dir/include/unifi_board.h"; then
    install -Dm644 "$board_header" "$source_dir/include/unifi_board.h"
fi
if [[ ! -f "$build_dir/build.ninja" || "${1:-}" == "--reconfigure" ]]; then
    mkdir -p "$build_dir"
    (cd "$build_dir" && "$source_dir/configure" --target-list="$target_list" --disable-docs --disable-werror)
fi
# Older QEMU configure runs may leave a Meson launcher in the build-local
# virtualenv after its Python module has been removed. Prefer that launcher
# only when it is executable and actually imports mesonbuild; otherwise use
# the Meson supplied by the active Nix development shell.
meson_bin="$build_dir/pyvenv/bin/meson"
meson_cache_invalid=0
if [[ ! -x "$meson_bin" ]] || ! "$meson_bin" --version >/dev/null 2>&1; then
    meson_cache_invalid=1
    meson_bin=$(command -v meson || true)
fi
[[ -n "$meson_bin" ]] || {
    echo "Meson is required; enter the .#qemu Nix development shell" >&2
    exit 1
}

# Ninja regenerates build.ninja with the Meson executable recorded when the
# build directory was configured. Reconfigure once when that recorded local
# virtualenv is stale; merely selecting another Meson for `configure` is not
# enough because Ninja would still invoke the dead wrapper afterwards.
if [[ "$meson_cache_invalid" == 1 && -f "$build_dir/build.ninja" && "${1:-}" != "--reconfigure" ]]; then
    exec "$0" --reconfigure
fi

# QEMU's Meson files enable io_uring when the library is found, but older
# configurations can omit the pkg-config include directory from C commands.
# Keep the cached build usable by passing the discovered headers explicitly.
qemu_c_args=${CFLAGS:-}
qemu_c_args="${qemu_c_args:+$qemu_c_args }-I$source_dir/include -I$repo_dir/integration/hw/unifi"
if pkg-config --exists liburing; then
    qemu_c_args="${qemu_c_args:+$qemu_c_args }$(pkg-config --cflags liburing)"
fi
qemu_c_link_args=${LDFLAGS:-}
if command -v ld.lld >/dev/null 2>&1; then
    qemu_c_link_args="${qemu_c_link_args:+$qemu_c_link_args }-fuse-ld=lld"
fi
if [[ -n "${QEMU_ANALYSIS_PROFILE_LIB:-}" ]]; then
    # board-ffi and analysis-profile are independent Rust staticlibs. Each
    # carries the same Rust runtime symbols, which LLD otherwise rejects even
    # though either definition is sufficient for the final QEMU executable.
    qemu_c_link_args="${qemu_c_link_args:+$qemu_c_link_args }-Wl,--allow-multiple-definition"
fi
if [[ -f "$build_dir/meson-private/coredata.dat" ]]; then
    cached_meson=$(
        strings "$build_dir/meson-private/coredata.dat" |
            rg -o -m1 'meson-[0-9]+\.[0-9]+\.[0-9]+' |
            sed 's/^meson-//' || true
    )
    current_meson=$($meson_bin --version)
    if [[ -n "$cached_meson" && "$cached_meson" != "$current_meson" ]]; then
        if [[ "${1:-}" != "--reconfigure" ]]; then
            echo "Meson cache uses $cached_meson; reconfiguring with $current_meson" >&2
            exec "$0" --reconfigure
        fi
    fi
fi
# `meson configure` rewrites coredata.dat whenever it runs, which makes Ninja
# regenerate build.ninja before every build and recompile everything when any
# option string moved. Remember the options this script last applied and touch
# Meson only when they actually differ.
meson_options=(
    -Dlibusb=enabled
    -Dc_args="$qemu_c_args"
    -Dc_link_args="$qemu_c_link_args"
    -Dunifi_board_lib="$repo_dir/target/release/libboard_ffi.a"
)
if [[ -n "${QEMU_ANALYSIS_PROFILE_LIB:-}" ]]; then
    meson_options+=(-Danalysis_profile_lib="$QEMU_ANALYSIS_PROFILE_LIB")
fi
case "$(uname -s)" in
    Linux)
        meson_options+=(
            -Dkvm=enabled
            -Dlinux_aio=enabled
            -Dsmartcard=enabled
            -Du2f=enabled
        )
        if pkg-config --exists blkio; then
            meson_options+=(-Dblkio=enabled)
        fi
        if [[ "${QEMU_ENABLE_XEN:-0}" == 1 ]]; then
            meson_options+=(-Dxen=enabled)
        fi
        if [[ "${QEMU_ENABLE_BLKIO:-0}" == 1 ]]; then
            meson_options+=(-Dblkio=enabled)
        fi
        ;;
    Darwin)
        meson_options+=(
            -Dhvf=enabled
            -Dsmartcard=enabled
        )
        ;;
esac
options_stamp="$build_dir/.unifi-meson-options"
options_desired=$(printf '%s\n' "${meson_options[@]}")
if [[ "${1:-}" == "--reconfigure" ]] ||
    [[ ! -f "$options_stamp" ]] ||
    [[ "$(cat "$options_stamp")" != "$options_desired" ]]; then
    "$meson_bin" configure "$build_dir" "${meson_options[@]}"
    printf '%s\n' "$options_desired" >"$options_stamp"
fi
ninja_bin=$(command -v ninja || true)
[[ -n "$ninja_bin" ]] || {
    echo "Ninja is required; enter the .#qemu Nix development shell" >&2
    exit 1
}
# An interrupted build leaves .ninja_deps truncated. Ninja then recovers into
# memory but keeps the damaged log on disk, so every recorded header scan reads
# back stale and the whole tree recompiles on each run. Rewrite it once.
if [[ -f "$build_dir/.ninja_deps" ]] &&
    "$ninja_bin" -C "$build_dir" -t deps 2>&1 >/dev/null |
    grep -q 'premature end of file'; then
    echo "ninja dependency log is truncated; recompacting" >&2
    "$ninja_bin" -C "$build_dir" -t recompact
fi
"$ninja_bin" -C "$build_dir" "$target_binary"
binary_path="$build_dir/$target_binary"
python3 "$repo_dir/scripts/write_engine_manifest.py" \
    --track "$track_dir" \
    --source-revision "$source_revision" \
    --binary "$binary_path" \
    --output "$build_dir/engine-build.json"
echo "$binary_path"
echo "$build_dir/engine-build.json"
