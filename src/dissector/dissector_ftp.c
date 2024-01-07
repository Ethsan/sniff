#include <stdio.h>
#include <string.h>
#include <err.h>

#include "dissector/dissector.h"

#define FTP_MAX_LINE 512

int dissector_ftp(struct packet_info *pi, const u_char *buffer, size_t len)
{
	char line[FTP_MAX_LINE + 1];
	size_t i, line_start;
	item *info = item_add_str(pi->root, "File Transfer Protocol (FTP)");
	int is_request = pi->port_dst == 21;

	if (len < 1) {
		warnx("Malformed FTP packet");
		item_set_str(info, "FTP [Malformed]");
		return -1;
	}

	line_start = 0;
	for (i = 0; i < len; i++) {
		if (buffer[i] != '\n')
			continue;

		size_t line_len = i - line_start;
		line_len = line_len > FTP_MAX_LINE ? FTP_MAX_LINE : line_len;

		memcpy(line, &buffer[line_start], line_len);
		line[line_len] = '\0';

		if (line_len > 0 && line[line_len - 1] == '\r')
			line[line_len - 1] = '\0';

		item *details = item_add_strf(info, "%s", line);

		char *arg = strchr(line, ' ');
		if (arg != NULL) {
			*arg = '\0';
			arg++;
		}

		item_add_strf(details, "%s Command: %s",
			      is_request ? "Request" : "Response", line);
		if (arg != NULL)
			item_add_strf(details, "%s Argument: %s",
				      is_request ? "Request" : "Response", arg);
	}
	return 0;
}
