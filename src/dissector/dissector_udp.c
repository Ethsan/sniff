#include <netinet/udp.h>
#include <stdlib.h>
#include <err.h>

#include "dissector/dissector.h"
#include "utils/udp_port.h"
#include "utils/string.h"

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

	return 0;

truncated:
	warnx("Malformed TCP header");
	item_set_str(items, "UDP [Malformed]");
	return -1;
}
