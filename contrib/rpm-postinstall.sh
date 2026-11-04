#!/bin/sh
set -eu

if [ ! -d /run/systemd/system ]; then
    exit 0
fi

systemctl daemon-reload
if [ "$1" -gt 1 ]; then
    systemctl try-restart headwire.service
fi
