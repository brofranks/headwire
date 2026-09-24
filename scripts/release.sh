#!/usr/bin/env bash
# Build every supported archive, with its distribution notices. Package the
# Linux binaries and notices for Debian and RPM installations as well.
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
    go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0

for platform in linux/amd64 linux/arm64 darwin/arm64 darwin/amd64; do
    export GOOS=${platform%/*} GOARCH=${platform#*/}
    name="headwire_${version}_${GOOS}_${GOARCH}"
    package="$work/$name"
    mkdir "$package"
    go build -trimpath -ldflags="-X brof.dev/headwire/internal/cli.version=$version" -o "$package/headwire" ./cmd/headwire
    collect_notices ./cmd/headwire "$package"
    cp LICENSE README.md contrib/headwire.conf.example "$package/"
    # The systemd unit and the native packages are Linux-only.
    if [[ $GOOS == linux ]]; then
        cp contrib/headwire.service "$package/"
    fi
    (cd "$package" && go version -m headwire) > "$package/modules.txt"
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
mv "$work/"*.tar.gz "$work/"*.deb "$work/"*.rpm "dist/$version/"
(cd "dist/$version" && sha256sum ./*.tar.gz ./*.deb ./*.rpm > SHA256SUMS)
printf 'Release artifacts: dist/%s\n' "$version"
