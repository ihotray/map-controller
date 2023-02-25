/*
 * alloctrace.c - trace alloc and free calls
 *
 * Copyright (C) 2019 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <dlfcn.h>

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#include "alloctrace.h"

static void *(*_malloc)(size_t);
static void (*_free)(void *);

static FILE *tracefile;

static void fprintf_timestamp_prefix(FILE *f)
{
	time_t now = time(NULL);
	struct tm *tm_now = localtime(&now);

	fprintf(f, "[%d-%02d-%02d %02d:%02d:%02d] ",
		tm_now->tm_year + 1900,
		tm_now->tm_mon + 1,
		tm_now->tm_mday,
		tm_now->tm_hour,
		tm_now->tm_min,
		tm_now->tm_sec);
}

void init_alloctrace(const char *prog)
{
	char f[128] = {0};

	if (trace_alloc) {
		snprintf(f, 127, "/tmp/%s_mtrace.log", prog);
		tracefile = fopen(f, "w+");
		if (tracefile)
			fprintf(stderr, "Successfully opened '%s'\n", f);
	}

	_malloc = dlsym(RTLD_NEXT, "malloc");
	if (_malloc == NULL)
		fprintf(tracefile, "Error! dlsym: %s\n", dlerror());

	_free = dlsym(RTLD_NEXT, "free");
	if (_free == NULL)
		fprintf(tracefile, "Error! dlsym: %s\n", dlerror());

	if (trace_alloc && tracefile) {
		fprintf_timestamp_prefix(tracefile);
		fprintf(tracefile, "Begin\n");
	}
}

void exit_alloctrace(void)
{
	if (trace_alloc && tracefile) {
		fprintf_timestamp_prefix(tracefile);
		fprintf(tracefile, "End\n");
		fclose(tracefile);
	}
}

void dbg_free(void *ptr, const char *by, const int lno)
{
	void *caller = __builtin_return_address(0);

	_free(ptr);

	if (trace_alloc && tracefile) {
		fprintf_timestamp_prefix(tracefile);
		fprintf(tracefile,
			"free  : %32s():%6d  [& = %12p]   ptr = %12p\n",
			by, lno, caller, ptr);
		fflush(tracefile);
	}
}

void *dbg_malloc(size_t size, const char *by, const int lno)
{
	void *ptr = NULL;
	void *caller = __builtin_return_address(0);

	ptr = _malloc(size);
	if (trace_alloc && tracefile && ptr) {
		fprintf_timestamp_prefix(tracefile);
		fprintf(tracefile,
			"malloc: %32s():%6d  [& = %12p]   ptr = %12p    size = %zu\n",
			by, lno, caller, ptr, size);
		fflush(tracefile);
	}

	return ptr;
}

void *dbg_calloc(size_t nmemb, size_t size, const char *by, const int lno)
{
	void *ptr = NULL;
	void *caller = __builtin_return_address(0);

	ptr = _malloc(nmemb * size);
	if (ptr)
		memset(ptr, 0, nmemb * size);

	if (trace_alloc && tracefile && ptr) {
		fprintf_timestamp_prefix(tracefile);
		fprintf(tracefile,
			"calloc: %32s():%6d  [& = %12p]   ptr = %12p    size = %zu\n",
			by, lno, caller, ptr, size);
		fflush(tracefile);
	}

	return ptr;
}
