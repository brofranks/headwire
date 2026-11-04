#!/bin/sh
set -eu

if [ "$1" != configure ] || [ ! -d /run/systemd/system ]; then
    exit 0
fi

systemctl daemon-reload
if [ -n "${2:-}" ]; then
    deb-systemd-invoke try-restart headwire.service
fi
