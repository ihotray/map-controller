CC		= gcc
MAPCNTLR_LIB_DIR	?= $(shell dirname $(PWD))
MAPCNTLR_LIB	= -L$(MAPCNTLR_LIB_DIR) -lmapcontroller
CMOCKA_LIB	= -l cmocka
LIBS		= $(MAPCNTLR_LIB) $(CMOCKA_LIB) -pthread -luci -lubus -lubox -ljson-c -lblobmsg_json -lnl-genl-3 -lnl-3 -ljson-validator -ljson-schema-validator -ljson-editor
LIBS 		+= -rdynamic -ldl
LIBS 		+= -lmaputils
CFLAGS		= -g -Wall -I../../src/core -I../../src/utils
LDFLAGS		= $(LIBS) -Wl,-rpath=$(MAPCNTLR_LIB_DIR) -I$(MAPCNTLR_LIB_DIR)
UNIT_TESTS	= unit_test_cntlr
FUNCTIONAL_TESTS	= functional_test_cntlr
UTILS 		= test_utils.o

VALGRIND	= valgrind --leak-check=full --show-reachable=no \
	--show-leak-kinds=all --errors-for-leak-kinds=all \
	--error-exitcode=1 --track-origins=yes

unit_test_cntlr: $(UTILS) unit_test_cntlr.o
	$(CC) -o $@ $^ $(LDFLAGS)

functional_test_cntlr: $(UTILS) functional_test_cntlr.o
	$(CC) -o $@ $^ $(LDFLAGS)

unit-test: $(UNIT_TESTS)
	$(foreach testprog, $(UNIT_TESTS), sudo $(VALGRIND) ./$(testprog);)

functional-test: $(FUNCTIONAL_TESTS)
	$(foreach testprog, $(FUNCTIONAL_TESTS), sudo $(VALGRIND) ./$(testprog);)

.PHONY: clean
clean:
	rm $(UNIT_TESTS) $(FUNCTIONAL_TESTS) *.o -fv
