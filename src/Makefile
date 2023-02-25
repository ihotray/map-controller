EXECS = mapcontroller
CFLAGS+=-I. -Iutils -D_GNU_SOURCE
CFLAGS+= -g -Wall -Werror

OBJS = \
	timer.o \
	utils/debug.o \
	utils/liblist.o \
	utils/utils.o \
	utils/alloctrace.o \
	wifi_opclass.o \
	allsta.o \
	allmac.o \
	cntlr_ubus.o \
	cntlr_ubus_dbg.o \
	cntlr.o \
	cntlr_map.o \
	cntlr_tlv.o \
	cntlr_cmdu.o \
	cntlr_acs.o \
	cntlr_map_debug.o \
	cmdu_validate.o \
	config.o \
	main.o \
	tlv_debug.o

OBJS += steer_module.o

LIBS = -lubus -lubox -ljson-c -lblobmsg_json -luci -pthread
LIBS += -rdynamic -ldl
LIBS += -leasy -lwifiutils
LIBS += -lieee1905 -lmaputil

plugin_subdirs ?= $(wildcard plugins/*/*)
plugin_sofile = $(wildcard $(d)/*.so)
plugin_files = $(foreach d, $(plugin_subdirs), $(plugin_sofile))
HOOKS = pre-commit

.PHONY: all check clean plugins FORCE

all: $(EXECS) plugins


%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

mapcontroller: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

plugins:
	@echo "$(plugin_subdirs)"
	for i in $(plugin_subdirs); do [ -d $$i ] && $(MAKE) -C $$i all; done

install-hooks:
	$(foreach hook, $(HOOKS), ln -s -f ../../hooks/$(hook) ../.git/hooks/$(hook);)

check: FORCE
	@cppcheck --quiet --enable=all --inconclusive --std=c99 \
		--suppress=variableScope \
		--suppress=unusedVariable \
		--suppress=unreadVariable \
		--suppress=funcArgNamesDifferent \
		--suppress=unusedFunction \
		--suppress=wrongPrintfScanfArgNum \
		--suppress=redundantAssignment \
		-I. -Iutils \
		. 2> cppcheck.out

test: CFLAGS += -fPIC
test: ${OBJS}
	${CC} ${LDFLAGS} -shared -o libmapcontroller.so ${OBJS} ${LIBS}

unit-test: coverage
	make -C ../test/cmocka unit-test MAPCNTLR_LIB_DIR=$(PWD)

coverage: CFLAGS  += -g -O0 -fprofile-arcs -ftest-coverage -fPIC
coverage: LDFLAGS += --coverage
coverage: test mapcontroller
	$(foreach testprog, $(CODECOVERAGE_SRC), $(GCOV) $(testprog);)


clean:
	rm -f *.o *.so utils/*.o utils/*.so $(EXECS)
	for i in $(plugin_subdirs); do [ -d $$i ] && $(MAKE) -C $$i clean; done

FORCE:
