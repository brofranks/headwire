#!/usr/bin/env bash
# Native development checks, shared by local runs and unsigned CI jobs.
set -euo pipefail
cd "$(dirname "$0")/.."
die() {
    echo "$1" >&2
    exit 1
}

coverage="dist/coverage/$(go env GOOS)-$(go env GOARCH)"
rm -rf "$coverage"
mkdir -p "$coverage"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export CGO_ENABLED=1
. scripts/goflags.sh
GOBIN="$work" go install tool
# ShellCheck is not a Go module, so its release is pinned here by digest.
case "$(uname -sm)" in
'Linux x86_64')
    platform=linux.x86_64
    sha256=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
    ;;
'Linux aarch64')
    platform=linux.aarch64
    sha256=12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588
    ;;
'Darwin arm64')
    platform=darwin.aarch64
    sha256=56affdd8de5527894dca6dc3d7e0a99a873b0f004d7aabc30ae407d3f48b0a79
    ;;
'Darwin x86_64')
    platform=darwin.x86_64
    sha256=3c89db4edcab7cf1c27bff178882e0f6f27f7afdf54e859fa041fca10febe4c6
    ;;
esac
curl -fsSL -o "$work/shellcheck.tar.xz" \
    "https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.$platform.tar.xz"
shasum -a 256 -c --quiet <<< "$sha256  $work/shellcheck.tar.xz"
tar -xJf "$work/shellcheck.tar.xz" -C "$work" --strip-components=1 \
    shellcheck-v0.11.0/shellcheck
# jactionlint finds shellcheck here for workflow run blocks.
PATH="$work:$PATH"

go mod tidy -diff
go mod verify
"$work/shfmt" -d scripts bridge contrib
"$work/shfmt" -f scripts bridge contrib | xargs shellcheck -x -P SCRIPTDIR -P .
"$work/jactionlint" --config-file /dev/null .github/workflows/* .github/dependabot.yml

# Include platform-specific source without traversing generated artifacts.
find cmd internal bridge scripts -name '*.go' -exec "$work/goimports" -d {} + > "$work/format.diff"
if [ -s "$work/format.diff" ]; then
    cat "$work/format.diff"
    die 'Run goimports on the files above.'
fi
go vet ./...
"$work/staticcheck" ./...
# The client commands must not link the data plane. cmd/headwire,
# bridge/apple and bridge/android add the engine on top of them. The daemon's
# own list proves the pattern still names those packages.
dataplane='wgengine|net/tstun|gvisor\.dev'
grep -qE "$dataplane" <<< "$(go list -deps ./cmd/headwire)" ||
    die 'the data-plane pattern no longer matches cmd/headwire.'
# Type-check every host's tagged source. The cgo-only bridges drop out of
# ./... here: bridge/apple, including its ios slice, needs the native macOS
# run above and bridge/apple/build.sh, and bridge/android needs the NDK and
# bridge/android/build.sh. -trimpath matches release.sh, whose arm64 builds
# then reuse these packages.
for os in linux darwin windows android; do
    GOOS=$os GOARCH=arm64 CGO_ENABLED=0 go vet -trimpath ./...
    GOOS=$os GOARCH=arm64 CGO_ENABLED=0 GOFLAGS="$GOFLAGS -trimpath" \
        "$work/staticcheck" ./...
    if grep -qE "$dataplane" <<< "$(GOOS=$os GOARCH=arm64 go list -deps ./internal/cli)"; then
        die "internal/cli links the data plane on $os."
    fi
done
go test -race -count=1 -coverpkg=./... -covermode=atomic -coverprofile="$coverage/coverage.out" ./...
go tool cover -func="$coverage/coverage.out" | tee "$coverage/functions.txt"
go tool cover -html="$coverage/coverage.out" -o "$coverage/index.html"
"$work/govulncheck" -test ./...
go list tool | xargs "$work/govulncheck"
