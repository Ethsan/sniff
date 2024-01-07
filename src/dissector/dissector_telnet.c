#include "dissector/dissector.h"
#include <arpa/telnet.h>
#include <string.h>

const char *get_command(const u_char code)
{
	switch (code) {
	case IAC:
		return "IAC";
	case DONT:
		return "DONT";
	case DO:
		return "DO";
	case WONT:
		return "WONT";
	case WILL:
		return "WILL";
	default:
		return "UNKNOWN";
	}
}

const char *get_subcommand(const u_char code)
{
	switch (code) {
	case TELOPT_ECHO:
		return "ECHO";
	case TELOPT_SGA:
		return "SGA";
	default:
		return "UNKNOWN";
	}
}

int parse_iac(item *info, const u_char *buffer, size_t len)
{
	if (len < 2)
		return -1; // Not enough data

	const char *command = get_command(buffer[0]);
	const char *subcommand = get_subcommand(buffer[1]);

	item_add_strf(info, "Command: %s", command);
	item_add_strf(info, "Subcommand: %s", subcommand);

	return 2; // Consumed 2 bytes
}

const u_char *add_data(item *info, const u_char *start, const u_char *end)
{
	if (start == end)
		return end;

	char str[end - start + 1];
	memcpy(str, start, end - start);

	for (int i = 0; i < end - start; i++) {
		char c = start[i];
		if (c == '\r' || c == '\n')
			str[i] = ' ';
		else if (c < 32 || c > 126)
			str[i] = '.';
		else
			str[i] = c;
	}

	item_add_strf(info, "Data: %s", str);

	return end;
}

int dissector_telnet(struct packet_info *pi, const u_char *buffer, size_t len)
{
	item *info = item_add_str(pi->root, "Telnet");

	const u_char *ptr = buffer, *end = buffer + len;

	while (buffer < end) {
		u_char c = *buffer;
		if (c == IAC) {
			ptr = add_data(info, ptr, buffer);
			int consumed =
				parse_iac(info, buffer + 1, end - buffer - 1);

			buffer += consumed;
			len -= consumed;
		}
		buffer++;
		len--;
	}

	add_data(info, ptr, end);

	return 0;
}
