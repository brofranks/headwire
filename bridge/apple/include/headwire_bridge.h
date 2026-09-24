// C ABI of the Headwire engine for Apple NetworkExtension providers.
//
// Functions returning char * return NULL on success or an error message. Every
// string handed out, errors included, is freed with HeadwireFree.
#ifndef HEADWIRE_BRIDGE_H
#define HEADWIRE_BRIDGE_H

#include <TargetConditionals.h>
#include <stdint.h>

// Each platform has one prepare function. Both return a handle plus the
// network settings as JSON. Apply the settings before HeadwireStart: the utun
// descriptor does not exist until then. A process holds at most one handle:
// preparing another fails until HeadwireStop. A changed configuration takes
// effect through stop and start. There is no reload.
#if TARGET_OS_OSX
// Loads /etc/headwire/<name>.conf (root- or self-owned, mode 0600).
char *HeadwirePrepareProfile(const char *name, int32_t *handle, char **settings);
#else
// Parses the configuration text.
char *HeadwirePrepareConfig(const char *config, int32_t *handle, char **settings);
#endif

// Starts the engine on a duplicate of tun_fd. A failed start keeps the handle,
// and so the process's one session, until HeadwireStop.
char *HeadwireStart(int32_t handle, int32_t tun_fd);

// Status fields ("" for pretty print), `ip [-4|-6]`, or `ping IP` for a running handle.
// Private and preshared keys are never included.
char *HeadwireStatus(int32_t handle, const char *field, char **out);

// ifname is the current default interface from NWPathMonitor, or "" if unknown.
// Also valid for a prepared handle, so the underlay is known before
// HeadwireStart binds its first socket behind a default route.
void HeadwireNetworkChanged(int32_t handle, const char *ifname);
void HeadwireStop(int32_t handle);

// The `headwire` command line for argv, without the program name, on the
// process's standard streams, returning the exit code. The host's own verbs
// (list, up, down, rungui) arrive here only for help or when malformed.
// Run off the main thread: request synchronously calls the host transport.
// context and the callback live until HeadwireCLI returns. The request string
// is borrowed for the callback only. Return NULL and set *out on success, or
// return an error string. Both strings must be malloc/strdup allocated and are
// freed by Go with free(). A NULL callback is valid for offline commands.
typedef char *(*HWRequest)(void *context, const char *request, char **out);
int32_t HeadwireCLI(int32_t argc, char **argv, HWRequest request, void *context);
void HeadwireFree(char *p);

#endif
