#pragma once

#include <stdio.h>

typedef struct item_list item_list;

typedef struct item item;

item_list *item_list_new();

item *item_list_add(item_list *tree);

item *item_list_add_str(item_list *tree, const char *str);

__attribute__((format(printf, 2, 3))) item *
item_list_add_strf(item_list *tree, const char *format, ...);

item *item_list_add_strfv(item_list *tree, const char *format, va_list args);

int item_set_str(item *item, const char *str);

item_list *item_add_sublist(item *item);

void item_list_free(item_list *tree);

int item_print(FILE *stream, item *item, int max_depth, int indent);

int item_list_print(FILE *stream, item_list *tree, int max_depth, int indent);
