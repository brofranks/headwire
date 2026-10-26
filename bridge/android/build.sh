#!/bin/bash
# Builds libheadwire.so for arm64-v8a and x86_64 into $1 with the Android NDK
# at ANDROID_NDK_ROOT or ANDROID_NDK_HOME, and checks that each library exports
# exactly the ABI in include/headwire_android.h, vetting each slice first.
# VERSION is what `version` prints, dev by default. Runs on any host with the
# NDK and the Go version go.mod requires.
set -euo pipefail
out=$(mkdir -p "${1:?usage: build.sh OUTDIR}" && cd "$1" && pwd)
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
. ../../scripts/goflags.sh
. ../../scripts/collect-notices.sh
install_notice_collector "$work/bin"
ndk=${ANDROID_NDK_ROOT:-${ANDROID_NDK_HOME:?set ANDROID_NDK_ROOT}}
bin=$(echo "$ndk"/toolchains/llvm/prebuilt/*/bin)
cp include/headwire_android.h "$out"

slice() ( # goarch abi triple
    export CGO_ENABLED=1 GOOS=android GOARCH=$1 CC=$bin/${3}26-clang
    # Pages are 16 KiB on arm64 devices since Android 15.
    export CGO_LDFLAGS="-Wl,-z,max-page-size=16384 -Wl,-soname,libheadwire.so"
    go vet -trimpath .
    go build -trimpath -ldflags="-X brof.dev/headwire/internal/cli.version=${VERSION:-dev}" -buildmode=c-shared -o "$out/$2/libheadwire.so" .
    rm "$out/$2/libheadwire.h" # the hand-written header is the contract
    want="HeadwireFree HeadwireNetworkChanged HeadwirePrepareConfig HeadwireStart HeadwireStatus HeadwireStop"
    got=$("$bin/llvm-nm" -D --defined-only "$out/$2/libheadwire.so" | awk '$2 == "T" && $3 ~ /^Headwire/ {print $3}' | sort -u | xargs)
    [ "$got" = "$want" ] || {
        echo "$2 exported symbols: $got" >&2
        exit 1
    }
    "$bin/llvm-readelf" -d "$out/$2/libheadwire.so" | grep -q 'SONAME.*\[libheadwire.so\]'
    "$bin/llvm-readelf" -lW "$out/$2/libheadwire.so" | awk '$1 == "LOAD" && $NF != "0x4000" {bad = 1} END {exit bad}' || {
        echo "$2: a LOAD segment is not 16 KiB aligned" >&2
        exit 1
    }
    "$CC" -Werror -Wall -Iinclude testdata/abi_smoke.c -L"$out/$2" -lheadwire -o "$work/abi_smoke-$2"
    [ "$1" = arm64 ] || return 0 # both slices link the same modules
    rm -rf "$out/notices"
    collect_notices . "$out/notices"
    { # the app bundles this as an asset
        printf 'Third-party licenses\n\nSources: headwire/LICENSE\n\n'
        cat ../../LICENSE
        cd "$out/notices/licenses"
        find ./* -type f | sort | while read -r f; do
            printf '\n\nSources: %s\n\n' "${f#./}"
            cat "$f"
        done
    } > "$out/ThirdPartyLicenses.txt"
)
slice arm64 arm64-v8a aarch64-linux-android
slice amd64 x86_64 x86_64-linux-android
