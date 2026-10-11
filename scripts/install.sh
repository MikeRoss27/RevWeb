#!/bin/sh
# Source checkout: build once, install CLI + TUI. Bundles use their bin/ directly.
set -eu
project_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
install_dir="${HOME}/.local/bin"
binary_dir=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --install-dir|--binary-dir)
            [ "$#" -ge 2 ] || { echo "Missing value for $1" >&2; exit 1; }
            case "$1" in
                --install-dir) install_dir=$2 ;;
                --binary-dir) binary_dir=$2 ;;
            esac
            shift 2 ;;
        -h|--help)
            echo 'Usage: sh scripts/install.sh [--install-dir DIR] [--binary-dir DIR]'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done
if [ -z "$binary_dir" ]; then
    if [ -f "$project_root/bin/webrev" ]; then
        binary_dir="$project_root/bin"
    else
        for tool in cargo rustc cmake; do
            command -v "$tool" >/dev/null 2>&1 || {
                echo "Missing $tool. See docs/installation.md (Rust 1.89+, C compiler, CMake)." >&2; exit 1;
            }
        done
        rustc --version | awk '{split($2,v,"."); exit !(v[1]>1 || (v[1]==1 && v[2]>=89))}' || {
            echo 'Rust 1.89+ required. Run rustup update stable.' >&2; exit 1;
        }
        (cd "$project_root" && cargo build --release --locked --package webrev-cli --package webrev-tui)
        binary_dir="$project_root/target/release"
    fi
fi
binary_dir=$(CDPATH='' cd -- "$binary_dir" && pwd)
manifest="$(dirname -- "$binary_dir")/SHA256SUMS"
for name in webrev webrev-tui; do
    [ -f "$binary_dir/$name" ] || { echo "Missing binary: $binary_dir/$name" >&2; exit 1; }
    if [ -f "$manifest" ]; then
        expected=$(awk -v name="bin/$name" '$2==name {print $1}' "$manifest")
        [ "${#expected}" -eq 64 ] || { echo "Missing/ambiguous checksum: $name" >&2; exit 1; }
        if command -v sha256sum >/dev/null 2>&1; then
            actual=$(sha256sum "$binary_dir/$name" | awk '{print $1}')
        else
            actual=$(shasum -a 256 "$binary_dir/$name" | awk '{print $1}')
        fi
        [ "$actual" = "$expected" ] || { echo "Checksum mismatch: $name" >&2; exit 1; }
    fi
done
mkdir -p -- "$install_dir"
install_dir=$(CDPATH='' cd -- "$install_dir" && pwd)
for name in webrev webrev-tui; do
    if [ "$binary_dir/$name" != "$install_dir/$name" ]; then
        install -m 755 "$binary_dir/$name" "$install_dir/$name"
    fi
    "$install_dir/$name" --version
done
echo "Installed CLI + TUI in $install_dir"
case ":$PATH:" in
    *":$install_dir:"*) ;;
    *) printf 'Add to your shell profile: export PATH="%s:$PATH"\n' "$install_dir" ;;
esac
echo 'Static scans are ready. Dynamic scans need Chrome/Chromium (CHROME can point to it).'
