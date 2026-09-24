#!/usr/bin/env bash
# Source once per build, and collect using the caller's compilation environment.
install_notice_collector() {
    GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) CGO_ENABLED=0 GOBIN="$1" \
        go install github.com/google/go-licenses/v2@v2.0.1
    notice_collector="$1/go-licenses"
}

collect_notices() { # package output-directory
    mkdir -p "$2"
    "$notice_collector" check --ignore=brof.dev/headwire \
        --allowed_licenses=Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,MIT "$1"
    "$notice_collector" report --ignore=brof.dev/headwire "$1" > "$2/dependencies.csv"
    "$notice_collector" save --ignore=brof.dev/headwire "$1" --save_path="$2/licenses"
    mkdir "$2/licenses/go" && cp "$(go env GOROOT)/LICENSE" "$2/licenses/go/LICENSE"
}
