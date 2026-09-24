#!/bin/bash
# Builds HeadwireBridge.xcframework (macOS arm64+x86_64, iOS arm64) into $1 and
# checks that the archive exports exactly the ABI in include/headwire_bridge.h.
# VERSION is what `version` prints, dev by default. Runs on a Mac with Xcode
# and the Go version go.mod requires.
set -euo pipefail
out=$(mkdir -p "${1:?usage: build.sh OUTDIR}" && cd "$1" && pwd)
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
. ../../scripts/goflags.sh
. ../../scripts/collect-notices.sh
install_notice_collector "$work/bin"

slice() ( # goos goarch sdk min-version-flag
    local arch=${2/amd64/x86_64} flags
    flags="-isysroot $(xcrun --sdk "$3" --show-sdk-path) $4 -arch $arch"
    CC=$(xcrun --sdk "$3" --find clang)
    export CGO_ENABLED=1 GOOS=$1 GOARCH=$2 CC CGO_CFLAGS=$flags CGO_LDFLAGS=$flags
    go build -trimpath -ldflags="-X brof.dev/headwire/internal/cli.version=${VERSION:-dev}" -buildmode=c-archive -o "$out/$1-$2.a" .
    [ "$2" = arm64 ] || return 0 # both darwin slices link the same modules
    rm -rf "$out/notices/$1"
    collect_notices . "$out/notices/$1"
    mkdir -p "$out/$1"
    { # the app bundles this as a resource
        printf 'Third-party licenses\n\nSources: headwire/LICENSE\n\n'
        cat ../../LICENSE
        cd "$out/notices/$1/licenses"
        find ./* -type f | sort | while read -r f; do
            printf '\n\nSources: %s\n\n' "${f#./}"
            cat "$f"
        done
    } > "$out/$1/ThirdPartyLicenses.txt"
)
slice darwin arm64 macosx -mmacosx-version-min=13.0
slice darwin amd64 macosx -mmacosx-version-min=13.0
slice ios arm64 iphoneos -miphoneos-version-min=16.0

for a in darwin-arm64:Profile ios-arm64:Config; do
    want="_HeadwireCLI _HeadwireFree _HeadwireNetworkChanged _HeadwirePrepare${a#*:} _HeadwireStart _HeadwireStatus _HeadwireStop"
    got=$(nm -gU "$out/${a%:*}.a" 2> /dev/null | awk '$2 == "T" && $3 ~ /^_Headwire/ {print $3}' | sort -u | xargs)
    [ "$got" = "$want" ] || {
        echo "${a%:*} exported symbols: $got" >&2
        exit 1
    }
done

lipo -create "$out/darwin-arm64.a" "$out/darwin-amd64.a" -output "$out/macos.a"
cc -Iinclude testdata/abi_smoke.c "$out/macos.a" -framework CoreFoundation -framework Security -framework IOKit -lresolv -o "$out/abi_smoke"
"$out/abi_smoke"

rm -rf "$out/HeadwireBridge.xcframework"
xcodebuild -create-xcframework \
    -library "$out/macos.a" -headers include \
    -library "$out/ios-arm64.a" -headers include \
    -output "$out/HeadwireBridge.xcframework"
