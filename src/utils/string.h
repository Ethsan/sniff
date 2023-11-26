#pragma once

#include <err.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

// Same as strdup but use alloca instead of malloc
#define strdupa(s)                                             \
	({                                                     \
		const char *__old = (s);                       \
		size_t __len = strlen(__old) + 1;              \
		char *__new = (char *)__builtin_alloca(__len); \
		(char *)memcpy(__new, __old, __len);           \
	})

static inline char *new_strv(const char *format, va_list args)
{
	char *str;
	size_t size;
	va_list cp_args;

	va_copy(cp_args, args);
	size = vsnprintf(NULL, 0, format, cp_args);
	va_end(cp_args);

	if ((str = malloc(size + 1)) == NULL)
		err(EXIT_FAILURE, "malloc");

	va_copy(cp_args, args);
	vsnprintf(str, size + 1, format, cp_args);
	va_end(cp_args);

	return str;
}

static inline __attribute__((format(printf, 1, 2))) char *
new_str(const char *format, ...)
{
	va_list args;
	char *ret;

	va_start(args, format);
	ret = new_strv(format, args);
	va_end(args);

	return ret;
}

static inline char *hexdump(const void *data, size_t size)
{
	const unsigned char *ptr = data;
	char *str = malloc(size * 3 + 1);

	if (str == NULL)
		err(EXIT_FAILURE, "malloc");

	for (size_t i = 0; i < size; i++)
		sprintf(str + i * 3, "%02x ", ptr[i]);

	return str;
}

// Same as above but use alloca instead of malloc
#define hexdumpa(data, size)                                           \
	({                                                             \
		const unsigned char *__ptr = (data);                   \
		char *__str = alloca((size)*3 + 1);                    \
		for (size_t __i = 0; __i < (size); __i++)              \
			sprintf(__str + __i * 3, "%02x ", __ptr[__i]); \
		__str;                                                 \
	})
