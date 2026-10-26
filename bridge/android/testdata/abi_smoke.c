// Links libheadwire.so through the hand-written header, calling every export
// once so each name the header declares must resolve. It does not check that
// the prototypes match the exports. It only compiles and links: the build host
// runs no Android code.
#include <stdlib.h>
#include "headwire_android.h"

static int32_t protect(void *context, int32_t fd) {
	(void)context;
	(void)fd;
	return 1;
}

int main(void) {
	int32_t handle = 0;
	char *settings = NULL, *out = NULL;
	HeadwireFree(HeadwirePrepareConfig("", &handle, &settings));
	HeadwireFree(HeadwireStart(handle, -1, protect, NULL));
	HeadwireFree(HeadwireStatus(handle, "", &out));
	HeadwireFree(HeadwireNetworkChanged(handle, "wlan0", "[]"));
	HeadwireStop(handle);
	return 0;
}
