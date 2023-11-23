#include <stdarg.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include "item_list.h"

struct item {
	char *str;

	item_list *parent;
	item_list *child;

	item *next;
	item *prev;
};

struct item_list {
	item *parent;

	item *start;
	item *end;
};

char *new_strv(const char *format, va_list args)
{
	char *str;
	size_t size;
	va_list cp_args;

	va_copy(cp_args, args);
	size = vsnprintf(NULL, 0, format, args);
	va_end(cp_args);

	if ((str = malloc(size + 1)) == NULL)
		err(EXIT_FAILURE, "malloc");

	vsnprintf(str, size + 1, format, args);

	return str;
}

__attribute__((format(printf, 1, 2))) char *new_str(const char *format, ...)
{
	va_list args;
	char *ret;

	va_start(args, format);
	ret = new_strv(format, args);
	va_end(args);

	return ret;
}

item_list *item_list_new()
{
	item_list *t;

	if ((t = malloc(sizeof(item_list))) == NULL)
		err(EXIT_FAILURE, "malloc");

	*t = (item_list){ 0 };

	return t;
}

item *item_list_add(item_list *list)
{
	item *i;

	if ((i = malloc(sizeof(item))) == NULL)
		err(EXIT_FAILURE, "malloc");

	*i = (item){ .str = NULL,
		     .parent = list,
		     .child = NULL,
		     .next = NULL,
		     .prev = NULL };

	if (list->start == NULL) {
		list->start = i;
		list->end = i;
	} else {
		list->end->next = i;
		i->prev = list->end;
		list->end = i;
	}

	return i;
}

item *item_list_add_str(item_list *list, const char *text)
{
	item *i;
	char *str;
	size_t size;

	size = strlen(text);
	if ((str = malloc(size + 1)) == NULL)
		err(EXIT_FAILURE, "malloc");

	memmove(str, text, size + 1);

	i = item_list_add(list);
	i->str = str;

	return i;
}

item *item_list_add_strf(item_list *list, const char *format, ...)
{
	va_list args;
	item *i;

	va_start(args, format);
	i = item_list_add_strfv(list, format, args);
	va_end(args);

	return i;
}

item *item_list_add_strfv(item_list *list, const char *format, va_list args)
{
	va_list cp_args;
	char *str;
	item *i;

	va_copy(cp_args, args);
	str = new_strv(format, cp_args);
	va_end(cp_args);

	i = item_list_add(list);
	i->str = str;

	return i;
}

item_list *item_add_sublist(item *item)
{
	item_list *t;

	t = item_list_new();

	item->child = t;
	t->parent = item;

	return t;
}

void item_free(item *item)
{
	if (item->child != NULL)
		item_list_free(item->child);
	if (item->str != NULL)
		free(item->str);
	free(item);
}

void item_list_free(item_list *list)
{
	item *i;

	for (i = list->start; i != NULL; i = i->next)
		item_free(i);

	free(list);
}

int item_print(FILE *stream, item *item, int max_depth, int indent)
{
	if (fprintf(stream, "%*s%s\n", indent, "\t", item->str) < 0)
		return -1;
	if (item->child != NULL)
		item_list_print(stream, item->child, max_depth, indent + 1);
	return 0;
}

int item_list_print(FILE *stream, item_list *list, int max_depth, int indent)
{
	item *i;

	for (i = list->start; i != NULL; i = i->next)
		if (item_print(stream, i, max_depth, indent) < 0)
			return -1;

	return 0;
}
