#include <netinet/udp.h>
#include <stdlib.h>
#include <err.h>

#include "dissector/dissector.h"
#include "utils/udp_port.h"
#include "utils/string.h"

int dissector_next_layer(struct packet_info *pi, const u_char *buffer,
			 size_t len, uint16_t src, uint16_t dst)
{
	if (src == 53 || dst == 53)
		return dissector_dns(pi, buffer, len);
	else if (src == 67 || dst == 67 || src == 68 || dst == 68)
		return dissector_bootp(pi, buffer, len);
	return 0;
}

int dissector_udp(struct packet_info *pi, const u_char *buffer, size_t len)
{
	uint16_t src, dst, ulen, sum;

	item *items = item_add_str(pi->root, "UDP");

	if (len < sizeof(struct udphdr))
		goto truncated;

	struct udphdr *udp = (struct udphdr *)buffer;

	src = ntohs(udp->uh_sport);
	dst = ntohs(udp->uh_dport);
	ulen = ntohs(udp->uh_ulen);
	sum = ntohs(udp->uh_sum);

	item_add_strf(items, "Source Port: %s", get_udp_port(src));
	item_add_strf(items, "Destination Port: %s", get_udp_port(dst));
	item_add_strf(items, "Length: %u", ulen);
	item_add_strf(items, "Checksum: 0x%04x", sum);

	if (ulen < sizeof(struct udphdr)) {
		item_add_str(items, "[Truncated Payload]");
		goto truncated;
	}

	return dissector_next_layer(pi, buffer + sizeof(struct udphdr),
				    len - sizeof(struct udphdr), src, dst);

truncated:
	warnx("Malformed TCP header");
	item_set_str(items, "UDP [Malformed]");
	return -1;
}
