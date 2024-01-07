#include "dissector/dissector.h"
#include <string.h>

const char *get_smtp_command(const u_char *buffer, size_t len)
{
	char command[5];
	if (len < 4)
		return NULL;

	memcpy(command, buffer, 4);
	command[4] = '\0';

	if (strcmp(command, "HELO") == 0)
		return "HELO";
	else if (strcmp(command, "MAIL") == 0)
		return "MAIL FROM:";
	else if (strcmp(command, "RCPT") == 0)
		return "RCPT TO:";
	else if (strcmp(command, "DATA") == 0)
		return "DATA";
	else if (strcmp(command, "QUIT") == 0)
		return "QUIT";
	else
		return NULL;
}

const char *get_smtp_response(const u_char *buffer, size_t len)
{
	char response[4];
	if (len < 3)
		return "UNKNOWN";

	memcpy(response, buffer, 3);
	response[3] = '\0';

	if (strcmp(response, "220") == 0)
		return "Service ready";
	else if (strcmp(response, "221") == 0)
		return "Service closing transmission channel";
	else if (strcmp(response, "250") == 0)
		return "Requested mail action okay, completed";
	else if (strcmp(response, "354") == 0)
		return "Start mail input";
	else if (strcmp(response, "421") == 0)
		return "Service not available";
	else
		return "UNKNOWN";
}

int dissector_smtp(struct packet_info *pi, const u_char *buffer, size_t len)
{
	item *info = item_add_str(pi->root, "SMTP");

	int is_server = pi->port_src;

	const u_char *ptr = buffer, *end = buffer + len;

	while (buffer < end) {
		// Move to the end of the line
		while (buffer < end && *buffer != '\n')
			buffer++;

		if (is_server) {
			item_add_strf(info, "Response: %s",
				      get_smtp_response(ptr, buffer - ptr));
		} else {
			const char *command =
				get_smtp_command(ptr, buffer - ptr);
			if (command != NULL)
				item_add_strf(info, "Command: %s", command);
			else
				item_add_strf(info, "Data: %.*s",
					      (int)(buffer - ptr), ptr);
		}
		// Skip the newline
		if (buffer < end)
			buffer++;
	}

	return 0;
}
