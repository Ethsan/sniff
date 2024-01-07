#include <assert.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "dissector.h"
#include "bootp.h"
#include "utils/string.h"

#define DHCP_VENDOR_SIZE 312

const char *get_message_type(uint8_t msg_type)
{
	switch (msg_type) {
	case 1:
		return "DISCOVER";
	case 2:
		return "OFFER";
	case 3:
		return "REQUEST";
	case 4:
		return "DECLINE";
	case 5:
		return "ACK";
	case 6:
		return "NAK";
	case 7:
		return "RELEASE";
	case 8:
		return "INFORM";
	default:
		return "Unknown";
	}
}

void handle_vendor_option(item *items, uint8_t opt_type, uint8_t opt_length,
			  const u_char *opt_ptr)
{
	char buf[CHAR_MAX + 1]; // +1 for '\0'
	static_assert(sizeof(buf) >= INET_ADDRSTRLEN, "buf too small");

	switch (opt_type) {
	case 0: // Pad option
		break;
	case 1: // Subnet Mask
		if (opt_length != 4)
			return;
		inet_ntop(AF_INET, opt_ptr, buf, sizeof(buf));
		item_add_strf(items, "Subnet Mask: %s", buf);
		break;
	case 3: // Router
		if (opt_length % 4 != 0)
			return;
		for (int i = 0; i < opt_length; i += 4) {
			inet_ntop(AF_INET, opt_ptr + i, buf, sizeof(buf));
			item_add_strf(items, "Router: %s", buf);
		}
		break;
	case 6: // Domain Server
		if (opt_length % 4 != 0)
			return;
		for (int i = 0; i < opt_length; i += 4) {
			inet_ntop(AF_INET, opt_ptr + i, buf, sizeof(buf));
			item_add_strf(items, "DNS Server: %s", buf);
		}
		break;
	case 12: // Hostname
		memcpy(buf, opt_ptr, opt_length);
		buf[opt_length] = '\0';
		item_add_strf(items, "Hostname: %s", buf);
		break;
	case 15: // Domain Name
		memcpy(buf, opt_ptr, opt_length);
		buf[opt_length] = '\0';
		item_add_strf(items, "Domain Name: %s", buf);
		break;
	case 53: // DHCP Message Type
		if (opt_length != 1)
			return;
		uint8_t msg_type = *opt_ptr;
		item_add_strf(items, "DHCP Message Type: %u", msg_type);
		break;
	default:
		item_add_strf(items, "Unknown Option: %u", opt_type);
		break;
	}
}

const char *get_bootp_op(uint8_t op)
{
	switch (op) {
	case BOOTREQUEST:
		return "REQUEST";
	case BOOTREPLY:
		return "REPLY";
	default:
		return "Unknown";
	}
}

int dissector_bootp(struct packet_info *pi, const u_char *buffer, size_t len)
{
	item *items = item_add_str(pi->root, "BOOTP");

	if (len < sizeof(struct bootp))
		goto truncated;

	struct bootp *bootp = (struct bootp *)buffer;

	// clang-format off
	item_add_strf(items, "Operation: %s (%u)", get_bootp_op(bootp->bp_op), bootp->bp_op);
	item_add_strf(items, "Hardware Type: %u", bootp->bp_htype);
	item_add_strf(items, "Hardware Address Length: %u", bootp->bp_hlen);
	item_add_strf(items, "Hops: %u", bootp->bp_hops);
	item_add_strf(items, "Transaction ID: 0x%08x", ntohl(bootp->bp_xid));
	item_add_strf(items, "Seconds: %u", ntohs(bootp->bp_secs));
	item_add_strf(items, "Flags: 0x%04x", ntohs(bootp->bp_flags));
	item_add_strf(items, "Client IP Address: %s", inet_ntoa(bootp->bp_ciaddr));
	item_add_strf(items, "Your IP Address: %s", inet_ntoa(bootp->bp_yiaddr));
	item_add_strf(items, "Server IP Address: %s", inet_ntoa(bootp->bp_siaddr));
	item_add_strf(items, "Gateway IP Address: %s", inet_ntoa(bootp->bp_giaddr));
	// clang-format on

	// Handle options
	size_t opt_len = DHCP_VENDOR_SIZE;
	const u_char *opt_ptr = &bootp->bp_vend[0];

	// Check magic cookie
	const uint8_t magic_cookie[] = VM_RFC1048;
	if (memcmp(opt_ptr, magic_cookie, sizeof(magic_cookie)) != 0)
		return 0;

	item *options = item_add_str(items, "Options");
	item_add_strf(options, "Magic Cookie: %s",
		      hexdumpa(magic_cookie, sizeof(magic_cookie)));

	opt_ptr += sizeof(magic_cookie);
	opt_len -= sizeof(magic_cookie);

	while (opt_len > 0) {
		uint8_t opt_type = *opt_ptr++;

		if (opt_type == 0) { // Pad option
			opt_len--;
			continue;
		}
		if (opt_type == 255) // End option
			break;

		if (opt_type == 53) // DHCP Message Type
			item_set_str(items, "BOOTP/DHCP");

		uint8_t opt_length = *opt_ptr++;

		if (opt_length > opt_len)
			goto truncated;

		handle_vendor_option(options, opt_type, opt_length, opt_ptr);

		opt_ptr += opt_length;
		opt_len -= opt_length + 2;
	}

	return 0;

truncated:
	warnx("Truncated BOOTP/DHCP packet");
	item_set_str(items, "BOOTP/DHCP [Truncated]");
	return -1;
}
