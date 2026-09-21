{
  description = "MachineEmu QEMU engine builds (unifi-10.2 track, analysis track, host-kernel guard)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.nixpkgs-stable.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { nixpkgs, nixpkgs-stable, ... }:
    let
      # tracks/unifi-10.2/track.toml declares x86_64-linux as the supported
      # host; aarch64-linux evaluates too. The graphics and KVM dependencies
      # this shell pulls in are Linux-only, so Darwin is not offered.
      systems = [
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;

            overlays = [
              (final: prev: {
                # libcap-ng's test suite does not link against static musl:
                # file_caps_test.c defines its own fgetxattr/fsetxattr, which
                # musl's libc.a already provides. Only the static build (which
                # pkgsStatic.qemu-user pulls in via glib) is affected.
                libcap_ng = prev.libcap_ng.overrideAttrs (
                  nixpkgs.lib.optionalAttrs prev.stdenv.hostPlatform.isMusl { doCheck = false; }
                );
              })
            ];
          };
          pkgsStable = import nixpkgs-stable { inherit system; };

          # Everything scripts/build-unifi-10.2.sh and
          # scripts/build-analysis-unifi-10.2.sh need on PATH or through
          # pkg-config. QEMU's configure auto-detects most of these, so a
          # missing entry silently drops a device instead of failing the build.
          qemuBuildPackages =
            with pkgs;
            [
              # Native compiler and build orchestration.
              gcc
              binutils
              gnumake
              meson
              ninja
              pkg-config
              cacert

              # QEMU's Rust build and bindgen integration, plus the workspace
              # crates (board-ffi, analysis-profile) the build links in.
              rustc
              cargo
              rustfmt
              clippy
              rust-bindgen
              clang
              lld
              llvmPackages.libclang

              # Core system libraries used by system-mode QEMU.
              glib
              glib.dev
              pixman
              zlib
              bzip2
              libffi
              libusb1
              libusb1.dev
              # QEMU's usb-redir guest device requires this parser, and the
              # remote-device host adapter uses the same frozen protocol.
              usbredir
              spice-protocol
              spice
              libslirp
              libcacard
              curl

              # Graphics stack, all auto-detected by QEMU's configure. epoxy is
              # the GL/EGL dispatch layer QEMU calls through; mesa-libgbm
              # allocates buffers straight from the DRM render node, which is
              # what -display egl-headless needs on a machine with no desktop
              # session; virglrenderer turns a guest's 3D commands into GL on
              # that context and is what enables virtio-vga-gl and
              # virtio-gpu-gl-pci. SDL2 and ncurses add the -display sdl and
              # curses backends.
              libepoxy
              # display-stream links EGL/GLES directly for its modifier-aware
              # QEMU DMABUF to VA-API bridge.
              libglvnd
              virglrenderer
              SDL2
              SDL2_image
              ncurses
              # rutabaga_gfx_ffi backs virtio-gpu-rutabaga, the gfxstream path
              # from crosvm; QEMU finds it through its pkg-config file.
              rutabaga_gfx

              # libpng gives screendump a PNG encoder; without it the analysis
              # build emits PPM while the stock binary emits PNG, and tooling
              # that reads the screenshots has to cope with both. libjpeg is the
              # VNC tight-JPEG encoder.
              libpng
              libjpeg

              # The display-stream encoder uses VA-API H.264 and GStreamer
              # for the viewer and fragmented-MP4 recording branches.
              gst_all_1.gstreamer
              gst_all_1.gst-plugins-base
              gst_all_1.gst-plugins-good
              gst_all_1.gst-plugins-bad
              libva-utils

              # Firmware/device-tree and image helpers used by the board tracks.
              (python3.withPackages (ps: [
                ps.pyyaml
                ps.pytest
              ]))
              dtc
              ubootTools
              xz
              zstd
              squashfs-tools-ng
              e2fsprogs
            ]
            ++ lib.optionals stdenv.hostPlatform.isLinux [
              systemdMinimal
              iw
              # Linux-only block and GPU backends: -Dlinux_aio, io_uring, and
              # the DRM/GBM path display-stream renders through.
              libaio
              liburing
              libcap_ng
              libseccomp
              libgbm
              libdrm
              # scripts/build-unifi-10.2.sh links u2f-emu's headers into the
              # QEMU source tree for -Du2f=enabled.
              libu2f-emu
            ];

          kernelPackages = pkgs.linuxPackages_latest;
          kernel = kernelPackages.kernel;
          kernelBuildTree = "${kernel.dev}/lib/modules/${kernel.modDirVersion}/build";

          stableKernel = pkgsStable.linuxPackages.kernel;
          stableKernelBuildTree = "${stableKernel.dev}/lib/modules/${stableKernel.modDirVersion}/build";
          analysisStableKernel = stableKernel.override {
            kernelPatches = (stableKernel.kernelPatches or [ ]) ++ [
              {
                name = "machineemu-analysis-rdtsc-vmx";
                patch = ./kernel/patches/0001-kvm-vmx-analysis-rdtsc-exit-nix.patch;
              }
            ];
          };
          analysisStableKernelBuildTree = "${analysisStableKernel.dev}/lib/modules/${analysisStableKernel.modDirVersion}/build";

          kernelDevPackagesFor =
            pkgSet: kern:
            (with pkgSet; [
              git
              ripgrep
              gnumake
              kmod
              bc
              bison
              flex
              openssl
              zlib
              elfutils
              pahole
              perl
            ])
            ++ kern.moduleBuildDependencies;

          devShell = pkgs.mkShellNoCC {
            packages =
              with pkgs;
              [
                git
                ripgrep
                jq
                curl
                squashfsTools
                nixfmt
                # Reference binary for comparison; the track binary is built by
                # scripts/build-unifi-10.2.sh out of .cache/.
                qemu
              ]
              ++ qemuBuildPackages;

            shellHook = ''
              export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
              export SSL_CERT_FILE="${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
              export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath qemuBuildPackages}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
              echo "track=unifi-10.2 qemu=$QEMU_SOURCE_VERSION ($QEMU_SOURCE_COMMIT)"
              echo "Fetch:   scripts/fetch-unifi-10.2.sh"
              echo "Build:   scripts/build-unifi-10.2.sh"
              echo "Analysis: scripts/build-analysis-10.2.sh"
            '';

            env = {
              PYTHONDONTWRITEBYTECODE = "1";
              LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
              SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
              # Kept in step with tracks/unifi-10.2/track.toml [source].
              QEMU_SOURCE_VERSION = "10.2.4";
              QEMU_SOURCE_COMMIT = "3e0bcba1ca7d6607ca49a988d165f052a3a53323";
            };
          };
        in
        {
          qemu = devShell;
          default = devShell;
        }
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          qemu-xen = pkgs.mkShellNoCC {
            inputsFrom = [ devShell ];
            packages = [ pkgs.xen ];
            shellHook = ''
              export QEMU_ENABLE_XEN=1
            '';
          };

          kernel = pkgs.mkShell {
            packages = kernelDevPackagesFor pkgs kernel;
            shellHook = ''
              export KDIR="${kernelBuildTree}"
              export KERNELRELEASE="${kernel.modDirVersion}"
              export ANALYSIS_KVM_MODULE_DIR="$PWD/kernel/analysis-kvm"
              echo "kernel channel=unstable/latest"
              echo "KDIR=$KDIR"
              echo "KERNELRELEASE=$KERNELRELEASE"
              echo "Build with: scripts/build-analysis-kvm-module.sh"
            '';
          };

          kernel-stable = pkgsStable.mkShell {
            packages = kernelDevPackagesFor pkgsStable stableKernel;
            shellHook = ''
              export KDIR="''${KDIR:-${stableKernelBuildTree}}"
              export KERNELRELEASE="''${KERNELRELEASE:-${stableKernel.modDirVersion}}"
              export LINUX_SRC_TARBALL="''${LINUX_SRC_TARBALL:-${stableKernel.src}}"
              export ANALYSIS_KVM_MODULE_DIR="$PWD/kernel/analysis-kvm"
              echo "kernel channel=stable"
              echo "KDIR=$KDIR"
              echo "KERNELRELEASE=$KERNELRELEASE"
              echo "Build with: scripts/build-analysis-kvm-module.sh"
            '';
          };

          kernel-analysis-stable = pkgsStable.mkShell {
            packages = kernelDevPackagesFor pkgsStable analysisStableKernel;
            shellHook = ''
              export KDIR="${analysisStableKernelBuildTree}"
              export KERNELRELEASE="${analysisStableKernel.modDirVersion}"
              export ANALYSIS_KVM_MODULE_DIR="$PWD/kernel/analysis-kvm"
              echo "kernel channel=stable + analysis RDTSC VMX patch"
              echo "KDIR=$KDIR"
              echo "KERNELRELEASE=$KERNELRELEASE"
              echo "Kernel out: ${analysisStableKernel}"
              echo "Kernel modules: ${analysisStableKernel.modules}"
            '';
          };
        }
      );

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
    };
}
