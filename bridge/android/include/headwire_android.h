// C ABI of the Headwire engine for an Android VpnService.
//
// Functions returning char * return NULL on success or an error message. Every
// string handed out, errors included, is freed with HeadwireFree.
#ifndef HEADWIRE_ANDROID_H
#define HEADWIRE_ANDROID_H

#include <stdint.h>

// Parses the configuration text and returns a handle plus the network settings
// as JSON: mtu, ipv4Addresses, ipv4Routes, ipv6Addresses, ipv6Routes (each a
// list of {address, bits}), dnsServers and dnsSearch. An empty list may be
// absent or null. Apply them to the VpnService.Builder, MTU included, before
// HeadwireStart: the tunnel descriptor does not exist until then. A process
// holds at most one handle: preparing another fails until HeadwireStop. A
// changed configuration takes effect through stop and start. There is no
// reload.
char *HeadwirePrepareConfig(const char *config, int32_t *handle, char **settings);

// Called from the engine for every socket it opens on the underlay; return
// nonzero after VpnService.protect succeeded. It runs on Go threads, so the
// host attaches them to the JVM itself. context lives until HeadwireStop
// returns.
typedef int32_t (*HWProtect)(void *context, int32_t fd);

// Starts the engine on tun_fd, the detached descriptor VpnService.establish
// returned, which the engine owns from here on. Push the network state with
// HeadwireNetworkChanged first, since the engine binds its sockets here. A
// failed start keeps the handle, and so the process's one session, until
// HeadwireStop.
char *HeadwireStart(int32_t handle, int32_t tun_fd, HWProtect protect, void *context);

// Status fields ("" for pretty print), `ip [-4|-6]`, or `ping IP` for a running
// handle. Private and preshared keys are never included.
char *HeadwireStatus(int32_t handle, const char *field, char **out);

// ifname is the interface of the current default network from
// ConnectivityManager, or "" if there is none. interfaces is the JSON list of
// the device's underlay interfaces, the tunnel's own excluded:
//
//   [{"name":"wlan0","index":3,"mtu":1500,"up":true,
//     "addresses":["192.168.1.5/24","fe80::1/64"]}]
//
// The engine cannot enumerate interfaces itself and sees no network until the
// first push. Also valid for a prepared handle. A malformed list, or a handle
// that does not hold the session, is an error and leaves the previous state in
// place.
char *HeadwireNetworkChanged(int32_t handle, const char *ifname, const char *interfaces);
void HeadwireStop(int32_t handle);
void HeadwireFree(char *p);

#endif
