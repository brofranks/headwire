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
GOBIN="$work" go install golang.org/x/tools/cmd/goimports@v0.50.0
GOBIN="$work" go install honnef.co/go/tools/cmd/staticcheck@v0.8.1
GOBIN="$work" go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
GOBIN="$work" go install mvdan.cc/sh/v3/cmd/shfmt@v3.14.1
GOBIN="$work" go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
python3 -m venv "$work/venv"
"$work/venv/bin/pip" install -q shellcheck-py==0.11.0.1
# actionlint finds shellcheck here for workflow run blocks.
PATH="$work/venv/bin:$PATH"

go mod tidy -diff
go mod verify
"$work/shfmt" -d scripts bridge
"$work/shfmt" -f scripts bridge | xargs shellcheck -x -P SCRIPTDIR -P .
"$work/actionlint" .github/workflows/*

# Include platform-specific source without traversing generated artifacts.
find cmd internal bridge -name '*.go' -exec "$work/goimports" -d {} + > "$work/format.diff"
if [ -s "$work/format.diff" ]; then
    cat "$work/format.diff"
    die 'Run goimports on the files above.'
fi
go vet ./...
"$work/staticcheck" ./...
# The client commands must not link the data plane. cmd/headwire and
# bridge/apple add the engine on top of them. The daemon's own list proves
# the pattern still names those packages.
dataplane='wgengine|net/tstun|gvisor\.dev'
grep -qE "$dataplane" <<< "$(go list -deps ./cmd/headwire)" ||
    die 'the data-plane pattern no longer matches cmd/headwire.'
if grep -qE "$dataplane" <<< "$(go list -deps ./internal/cli)"; then
    die 'internal/cli links the data plane.'
fi
# Type-check the other host's tagged source. Cgo-only bridge/apple, including
# its ios slice, needs the native macOS run above and bridge/apple/build.sh.
for os in linux darwin; do
    GOOS=$os GOARCH=arm64 CGO_ENABLED=0 go vet ./...
    GOOS=$os GOARCH=arm64 CGO_ENABLED=0 "$work/staticcheck" ./...
done
go test -race -count=1 -coverpkg=./... -covermode=atomic -coverprofile="$coverage/coverage.out" ./...
go tool cover -func="$coverage/coverage.out" | tee "$coverage/functions.txt"
go tool cover -html="$coverage/coverage.out" -o "$coverage/index.html"
"$work/govulncheck" -test ./...
