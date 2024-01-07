#include "dissector.h"

#include <stdlib.h>
#include <string.h>

int dissector_http_request(struct packet_info *pi, const u_char *buffer,
			   size_t len)
{
	item *info = item_add_str(pi->root, "HyperText Transfer Protocol");

	char *method = NULL, *uri = NULL, *version = NULL;
	const u_char *ptr = buffer, *end = buffer + len;

	// Parse the first line
	while (buffer < end && *buffer != ' ' && *buffer != '\n')
		buffer++;
	if (buffer == end || *buffer == '\n')
		goto malformed;

	method = strndup((const char *)ptr, buffer - ptr);
	ptr = ++buffer;

	while (buffer < end && *buffer != ' ' && *buffer != '\n')
		buffer++;
	if (buffer == end || *buffer == '\n')
		goto malformed;

	uri = strndup((const char *)ptr, buffer - ptr);
	ptr = ++buffer;

	while (buffer < end && *buffer != '\r')
		buffer++;
	if (buffer == end)
		goto malformed;
	if (buffer + 1 == end || *(buffer + 1) != '\n')
		goto malformed;

	buffer += 2;
	ptr = buffer;

	version = strndup((const char *)ptr, buffer - ptr);

	item *first = item_add_strf(info, "%s %s %s", method, uri, version);
	item_add_strf(first, "Request Method: %s", method);
	item_add_strf(first, "Request URI: %s", uri);
	item_add_strf(first, "Request Version: %s", version);

	free(method);
	free(uri);
	free(version);
	method = uri = version = NULL;

	while (buffer < end) {
		// Move to the end of the line
		while (buffer < end && *buffer != '\n')
			buffer++;
		if (buffer == end)
			goto malformed;
		if (buffer + 1 == end || *(buffer + 1) != '\n')
			goto malformed;
		item_add_strf(info, "%.*s", (int)(ptr - buffer), ptr);
		buffer += 2;
	}

	return 0;
malformed:
	free(method);
	free(uri);
	free(version);
	item_set_strf(info, "HyperText Transfer Protocol [Malformed]");
	return -1;
}

int dissector_http(struct packet_info *pi, const u_char *buffer, size_t len)
{
	switch (pi->port_dst) {
	case 8080:
	case 80:
		return dissector_http_request(pi, buffer, len);
	default:
		return 0;
	}
}
