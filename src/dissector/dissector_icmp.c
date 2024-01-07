#include <stdio.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <err.h>

#include "dissector.h"
#include "utils/string.h"

const char *get_icmp_type(int type)
{
	switch (type) {
	case ICMP_ECHOREPLY:
		return "Echo Reply";
	case ICMP_DEST_UNREACH:
		return "Destination Unreachable";
	case ICMP_SOURCE_QUENCH:
		return "Source Quench";
	case ICMP_REDIRECT:
		return "Redirect (change route)";
	case ICMP_ECHO:
		return "Echo Request";
	case ICMP_TIME_EXCEEDED:
		return "Time Exceeded";
	case ICMP_PARAMETERPROB:
		return "Parameter Problem";
	case ICMP_TIMESTAMP:
		return "Timestamp Request";
	case ICMP_TIMESTAMPREPLY:
		return "Timestamp Reply";
	case ICMP_INFO_REQUEST:
		return "Information Request";
	case ICMP_INFO_REPLY:
		return "Information Reply";
	case ICMP_ADDRESS:
		return "Address Mask Request";
	case ICMP_ADDRESSREPLY:
		return "Address Mask Reply";
	default:
		return "Unknown";
	}
}

int dissector_icmp(struct packet_info *pi, const u_char *buffer, size_t len)
{
	int type, code;

	item *items = item_add(pi->root);

	if (len < sizeof(struct icmphdr)) {
		warnx("Malformed ICMP header");
		goto malformed;
	}

	struct icmphdr *icmp = (struct icmphdr *)buffer;

	buffer += sizeof(struct icmphdr);
	len -= sizeof(struct icmphdr);

	type = icmp->type;
	code = icmp->code;

	item_set_strf(items, "Internet Control Message Protocol: %s (%d)",
		      get_icmp_type(type), type);
	item_add_strf(items, "Type: %s (%d)", get_icmp_type(type), type);
	item_add_strf(items, "Code: %d", code);
	item_add_strf(items, "Checksum: 0x%04x", ntohs(icmp->checksum));

	if (type == ICMP_DEST_UNREACH) {
		if (len < sizeof(struct ip)) {
			warnx("Malformed ICMP payload");
			goto malformed;
		}

		struct ip *ip_header = (struct ip *)buffer;

		item *ip_item = item_add(items);
		item_set_strf(ip_item, "Original IP header");
		item_add_strf(ip_item, "Source IP: %s",
			      inet_ntoa(ip_header->ip_src));
		item_add_strf(ip_item, "Destination IP: %s",
			      inet_ntoa(ip_header->ip_dst));

		buffer += ip_header->ip_hl * 4;
		len -= ip_header->ip_hl * 4;
	}

	return 0;

malformed:
	item_set_strf(items, "Internet Control Message Protocol [Malformed]");
	return -1;
}
