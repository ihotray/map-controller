/*
 * alloctrace.h - trace heap memory alloc and free
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#ifndef ALLOCTRACE_H
#define ALLOCTRACE_H

extern int trace_alloc;

#define TRACE_ALLOC	0

#ifdef TRACE_ALLOC
extern void init_alloctrace(const char *progname);
extern void exit_alloctrace(void);
extern void *dbg_malloc(size_t size, const char *by, const int lno);
extern void dbg_free(void *ptr, const char *by, const int lno);
extern void *dbg_calloc(size_t nmemb, size_t size, const char *by,
	const int lno);

#define malloc(s)	dbg_malloc(s, __func__, __LINE__)
#define calloc(n, s)	dbg_calloc(n, s, __func__, __LINE__)
#define free(p)		dbg_free(p, __func__, __LINE__)
#else

static inline void init_alloctrace(const char *progname)
{
}

static inline void exit_alloctrace(void)
{
}

#define dbg_malloc
#define dbg_free
#define dbg_calloc

#endif /* TRACE_ALLOC */

#endif /* ALLOCTRACE_H */
