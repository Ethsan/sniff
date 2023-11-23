#pragma once

struct options {
	const char *interface;
	const char *file;

	const char *filter;

	int verbose;
};

void capture(struct options *opt);
