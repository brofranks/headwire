#!/usr/bin/env bash
# Source once per build to set the module mode and build tags every Headwire
# build shares. The tags drop upstream Tailscale features Headwire cannot
# reach: it exposes neither web interface, and it embeds wgengine without
# ipn/LocalBackend, so the control-plane features below have no entry point.
export GOFLAGS='-mod=readonly -tags=ts_omit_webclient,ts_omit_debugeventbus,ts_omit_serve,ts_omit_tailnetlock,ts_omit_syspolicy,ts_omit_peerapiserver,ts_omit_appconnectors,ts_omit_logtail,ts_omit_c2n'
