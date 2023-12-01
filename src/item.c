#include <stdarg.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include "item.h"
#include "utils/string.h"

struct item {
	char *str;

	item *next;
	item *prev;

	item *parent;

	item *first_child;
	item *last_child;
};

item *item_new()
{
	item *t;

	if ((t = malloc(sizeof(item))) == NULL)
		err(EXIT_FAILURE, "malloc");

	*t = (typeof(*t)){ 0 };

	return t;
}

item *item_new_str(const char *str)
{
	item *i = item_new();

	if ((i->str = strdup(str)) == NULL)
		err(EXIT_FAILURE, "strdup");

	return i;
}

item *item_new_strf(const char *format, ...)
{
	va_list args;
	item *i;

	va_start(args, format);
	i = item_new_strfv(format, args);
	va_end(args);

	return i;
}

item *item_new_strfv(const char *format, va_list args)
{
	item *i = item_new();
	i->str = new_strv(format, args);
	return i;
}

void item_add_child(item *parent, item *child)
{
	child->parent = parent;

	if (parent->first_child == NULL) {
		parent->first_child = child;
		parent->last_child = child;
	} else {
		parent->last_child->next = child;
		child->prev = parent->last_child;
		parent->last_child = child;
	}
}

void item_set_str(item *i, const char *str)
{
	if (i->str != NULL)
		free(i->str);
	if ((i->str = strdup(str)) == NULL)
		err(EXIT_FAILURE, "strdup");
}

void item_set_strf(item *i, const char *format, ...)
{
	va_list args;
	char *str;

	va_start(args, format);
	str = new_strv(format, args);
	va_end(args);

	if (i->str != NULL)
		free(i->str);
	i->str = str;
}

void item_set_strfv(item *i, const char *format, va_list args)
{
	char *str = new_strv(format, args);

	if (i->str != NULL)
		free(i->str);
	i->str = str;
}

item *item_add(item *parent)
{
	item *i = item_new();
	item_add_child(parent, i);
	return i;
}

item *item_add_str(item *parent, const char *str)
{
	item *i = item_new_str(str);
	item_add_child(parent, i);
	return i;
}

item *item_add_strf(item *parent, const char *format, ...)
{
	va_list args;
	item *i;

	va_start(args, format);
	i = item_add_strfv(parent, format, args);
	va_end(args);

	return i;
}

item *item_add_strfv(item *parent, const char *format, va_list args)
{
	item *i = item_new_strfv(format, args);
	item_add_child(parent, i);
	return i;
}

void item_free(item *i)
{
	if (i->str != NULL)
		free(i->str);
	free(i);
}

void item_free_all(item *root)
{
	item *i, *next;

	for (i = root->first_child; i != NULL; i = next) {
		next = i->next;
		item_free_all(i);
	}

	item_free(root);
}

int print_indent(FILE *stream, item *i, item *top)
{
	if (i->parent == top)
		return 0;

	if (print_indent(stream, i->parent, top) < 0)
		return -1;

	if (i->parent->next == NULL) {
		if (fprintf(stream, "    ") < 0)
			return -1;
	} else {
		if (fprintf(stream, "│   ") < 0)
			return -1;
	}
	return 0;
}

int print_list(FILE *stream, item *i, int max_depth, item *root);

int print_indented_item(FILE *stream, item *i, int max_depth, item *root)
{
	print_indent(stream, i, root);

	if (i->next == NULL) {
		if (fprintf(stream, "╰── ") < 0)
			return -1;
	} else {
		if (fprintf(stream, "├── ") < 0)
			return -1;
	}

	if (i->str != NULL) {
		if (fprintf(stream, "%s\n", i->str) < 0)
			return -1;
	} else {
		if (fprintf(stream, "\n") < 0)
			return -1;
	}

	if (max_depth != 0)
		if (print_list(stream, i, max_depth, root) < 0)
			return -1;

	return 0;
}

int print_list(FILE *stream, item *current, int max_depth, item *root)
{
	item *i;

	for (i = current->first_child; i != NULL; i = i->next) {
		if (print_indented_item(stream, i, max_depth - 1, root) < 0)
			return -1;
	}

	return 0;
}

int item_print(item *root, FILE *stream, int max_depth)
{
	if (fprintf(stream, "%s\n", root->str) < 0)
		return -1;
	return print_list(stream, root, max_depth, root);
}
