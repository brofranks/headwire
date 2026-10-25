#!/usr/bin/env bash
# Build every supported archive, with its distribution notices. Package the
# Linux binaries and notices for Debian and RPM installations as well, and
# bundle wintun.dll with the Windows binaries.
set -euo pipefail
cd "$(dirname "$0")/.."

# A development build is named by its UTC time.
version=${1:-dev-$(date -u +%Y%m%d%H%M%S)}
if [[ $# -gt 1 || ! $version =~ ^[[:alnum:]][[:alnum:].+_-]*$ ]]; then
    echo 'usage: scripts/release.sh [version]' >&2
    exit 2
fi

# Native package versions must begin with a digit.
case "$version" in
dev-*) package_version="0.0.0-$version" ;;
*)
    if [[ ! $version =~ ^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?(\+[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]; then
        echo 'release version must be semantic (for example v1.2.3) or dev-<stamp>' >&2
        exit 2
    fi
    package_version=${version#v}
    ;;
esac
export PACKAGE_VERSION="$package_version"

. scripts/goflags.sh
export CGO_ENABLED=0
export GOAMD64=v1 GOARM64=v8.0
export GOEXPERIMENT=
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
. scripts/collect-notices.sh
install_notice_collector "$work/bin"

GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) GOBIN="$work/bin" \
    go -C tools/release install github.com/goreleaser/nfpm/v2/cmd/nfpm

# The Wintun bindings wireguard-go uses load wintun.dll from the binary's
# directory. The release is the one tailscale.com's tsconst/wintun pins.
read -r wintun_url wintun_sha256 < <(go run scripts/wintun.go)
mkdir "$work/wintun"
curl -fsSL -o "$work/wintun/release.zip" "$wintun_url"
sha256sum -c --quiet <<< "$wintun_sha256  $work/wintun/release.zip"
unzip -q "$work/wintun/release.zip" -d "$work/wintun"

for platform in linux/amd64 linux/arm64 darwin/arm64 darwin/amd64 windows/amd64 windows/arm64; do
    export GOOS=${platform%/*} GOARCH=${platform#*/}
    name="headwire_${version}_${GOOS}_${GOARCH}"
    package="$work/$name"
    mkdir "$package"
    binary=headwire
    [[ $GOOS != windows ]] || binary=headwire.exe
    go build -trimpath -ldflags="-X brof.dev/headwire/internal/cli.version=$version" -o "$package/$binary" ./cmd/headwire
    collect_notices ./cmd/headwire "$package"
    cp LICENSE README.md contrib/headwire.conf.example "$package/"
    # The systemd unit and the native packages are Linux-only.
    if [[ $GOOS == linux ]]; then
        cp contrib/headwire.service "$package/"
    fi
    (cd "$package" && go version -m "$binary") > "$package/modules.txt"
    if [[ $GOOS == windows ]]; then
        cp "$work/wintun/wintun/bin/$GOARCH/wintun.dll" "$package/"
        mkdir "$package/licenses/wintun"
        cp "$work/wintun/wintun/LICENSE.txt" "$package/licenses/wintun/"
        # zip keeps file times in local time, and its format starts in 1980.
        find "$package" -exec touch -d 1980-01-01T00:00:00Z {} +
        (cd "$work" && find "$name" | LC_ALL=C sort | TZ=UTC0 zip -q -X "$name.zip" -@)
        continue
    fi
    tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
        -C "$work" -cf - "$name" | gzip -n > "$work/$name.tar.gz"
    [[ $GOOS == linux ]] || continue
    export PACKAGE_DIR="$package" PACKAGE_DOCS="$work/docs-$GOARCH"
    cp -a "$package" "$PACKAGE_DOCS"
    rm "$PACKAGE_DOCS/headwire" "$PACKAGE_DOCS/headwire.service"
    for format in deb rpm; do
        "$work/bin/nfpm" package --config contrib/nfpm.yaml --packager "$format" \
            --target "$work/$name.$format"
    done
done

# Publish only complete artifact sets, and never overwrite a previous local
# release.
mkdir -p dist
mkdir "dist/$version"
mv "$work/"*.tar.gz "$work/"*.zip "$work/"*.deb "$work/"*.rpm "dist/$version/"
(cd "dist/$version" && sha256sum ./*.tar.gz ./*.zip ./*.deb ./*.rpm > SHA256SUMS)
printf 'Release artifacts: dist/%s\n' "$version"
