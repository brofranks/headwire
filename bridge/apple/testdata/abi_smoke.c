// Links the archive through the hand-written header and drives the paths that
// need neither root nor a utun: the header and the exports must agree.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "headwire_bridge.h"

static int refused(const char *what, char *err) {
	if (!err) {
		fprintf(stderr, "%s: succeeded\n", what);
		return 1;
	}
	printf("%s: %s\n", what, err);
	HeadwireFree(err);
	return 0;
}

static char *request(void *context, const char *line, char **out) {
	int *calls = context;
	++*calls;
	if (strcmp(line, "ip -4") == 0 || strcmp(line, "") == 0) {
		*out = strdup("10.0.0.7\n");
		return NULL;
	}
	return strdup("test transport failure");
}

int main(void) {
	int32_t handle = 0;
	char *settings = NULL, *out = NULL;
	int bad = refused("prepare ../x", HeadwirePrepareProfile("../x", &handle, &settings));
	bad |= refused("start unprepared", HeadwireStart(7, -1));
	bad |= refused("status unknown", HeadwireStatus(7, "", &out));
	HeadwireNetworkChanged(7, "en0");
	HeadwireStop(7);
	char *argv[] = {"version"};
	bad |= HeadwireCLI(1, argv, NULL, NULL);
	int calls = 0;
	char *ip[] = {"ip", "-4"};
	bad |= HeadwireCLI(2, ip, request, &calls);
	char *show[] = {"show", "dump"};
	bad |= HeadwireCLI(2, show, request, &calls) != 1;
	char *invalid[] = {"ping"};
	bad |= HeadwireCLI(1, invalid, request, &calls) != 2;
	char *help[] = {"ping", "--help"};
	bad |= HeadwireCLI(2, help, request, &calls);
	char *ping[] = {"ping", "10.0.0.2"};
	bad |= HeadwireCLI(2, ping, request, &calls) != 1;
	bad |= HeadwireCLI(0, NULL, request, &calls);
	char *command_help[] = {"help", "up"};
	bad |= HeadwireCLI(2, command_help, request, &calls);
	bad |= calls != 3;
	return bad;
}
