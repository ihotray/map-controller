#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <json-c/json.h>

#include <easy/easy.h>
#include <wifi.h>	// FIXME: should not be included

#include "debug.h"
#include "utils.h"
#include "config.h"
#include "test_utils.h"
#include "cntlr.h"

#define CNTLR_FILE "/tmp/cntlr.test.log"
#define AGENT_FILE "/tmp/cntlr.test.log"

int cntlr_ap_caps(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

struct test_ctx {
	struct blob_buf bb;
	struct ubus_object radio;
	struct ubus_object ap;
	FILE *fp;
};

static int group_setup(void **state)
{
	struct test_ctx *ctx;

	ctx = calloc(1, sizeof(*ctx));

	start_test_logging();

	if (!ctx)
		return -1;

	remove(CNTLR_FILE);
	remove(AGENT_FILE);

	memset(&ctx->bb, 0, sizeof(struct blob_buf));

	*state = ctx;
	return 0;
}

static int setup(void **state)
{
	return 0;
}

static int teardown(void **state)
{
	stop_test_logging();

	return 0;
}

/* overload ubus_send_reply to prevent segfault*/
int ubus_send_reply(struct ubus_context *ctx, struct ubus_request_data *req,
		    struct blob_attr *msg)
{
	return 0;
}

static int group_teardown(void **state)
{
//	struct test_ctx *ctx = (struct test_ctx *) *state;

	blob_buf_free(&ctx->bb);
//	free(ctx);
	remove(CNTLR_FILE);
	remove(AGENT_FILE);
	return 0;
}

static void test_cmdu_comm(void **state)
{
	int rv;
	struct blob_buf bb = {0};
	struct controller c;

	// TODO: place in group setup
	c.ubus_ctx = ubus_connect(NULL);
	blob_buf_init(&bb, 0);

	rv = cntlr_ap_caps(NULL, &c.obj, NULL, NULL, bb.head);

	assert_int_equal(rv, 0);

	assert_true(!compare_files(CNTLR_FILE, AGENT_FILE));
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_cmdu_comm, setup, teardown),
	};

	return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
