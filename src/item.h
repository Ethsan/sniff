#pragma once

#include <stdio.h>

typedef struct item item;

item *item_new();

item *item_new_str(const char *str);

item *item_new_strf(const char *format, ...);

item *item_new_strfv(const char *format, va_list args);

void item_add_child(item *parent, item *child);

void item_set_str(item *item, const char *str);

void item_set_strf(item *item, const char *format, ...);

void item_set_strfv(item *item, const char *format, va_list args);

item *item_new_child(item *parent);

item *item_new_child_str(item *parent, const char *str);

item *item_new_child_strf(item *parent, const char *format, ...);

item *item_new_child_strfv(item *parent, const char *format, va_list args);

void item_free(item *item);

void item_free_all(item *item);

int item_print(item *item, FILE *out, int max_depth);
