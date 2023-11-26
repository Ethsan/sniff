#include <netinet/ip.h>
#include <stddef.h>
#include <string.h>

#include "dissector.h"
#include "utils/string.h"

const char *get_protocol(int protocol)
{
	if (protocol == IPPROTO_ICMP)
		return "ICMP";
	else if (protocol == IPPROTO_IGMP)
		return "IGMP";
	else if (protocol == IPPROTO_IPIP)
		return "IPIP";
	else if (protocol == IPPROTO_TCP)
		return "TCP";
	else if (protocol == IPPROTO_EGP)
		return "EGP";
	else if (protocol == IPPROTO_PUP)
		return "PUP";
	else if (protocol == IPPROTO_UDP)
		return "UDP";
	else if (protocol == IPPROTO_IDP)
		return "IDP";
	else if (protocol == IPPROTO_TP)
		return "TP";
	else if (protocol == IPPROTO_DCCP)
		return "DCCP";
	else if (protocol == IPPROTO_IPV6)
		return "IPv6";
	else if (protocol == IPPROTO_RSVP)
		return "RSVP";
	else if (protocol == IPPROTO_GRE)
		return "GRE";
	else if (protocol == IPPROTO_ESP)
		return "ESP";
	else if (protocol == IPPROTO_AH)
		return "AH";
	else if (protocol == IPPROTO_MTP)
		return "MTP";
	else if (protocol == IPPROTO_BEETPH)
		return "BEETPH";
	else if (protocol == IPPROTO_ENCAP)
		return "ENCAP";
	else if (protocol == IPPROTO_PIM)
		return "PIM";
	else if (protocol == IPPROTO_COMP)
		return "COMP";
	else if (protocol == IPPROTO_SCTP)
		return "SCTP";
	else if (protocol == IPPROTO_UDPLITE)
		return "UDPLITE";
	else if (protocol == IPPROTO_RAW)
		return "RAW";
	return "Unknown";
}

int dissector_transport(int protocol, struct packet_info *pi,
			const u_char *buffer, size_t len)
{
	if (protocol == IPPROTO_TCP)
		return dissector_tcp(pi, buffer, len);
	else if (protocol == IPPROTO_UDP)
		return dissector_udp(pi, buffer, len);
	return 0;
}

const char *get_option(int type)
{
	switch (type) {
	case 0:
		return "End of Options List (EOL)";
	case 1:
		return "No Operation (NOP)";
	case 3:
		return "Loose Source Route (LSR)";
	case 7:
		return "Record Route (RR)";
	case 68:
		return "Internet Timestamp (TS)";
	case 131:
		return "Strict Source Route (SSR)";
	case 136:
		return "Traceroute (TR)";
	default:
		return "Unknown";
	}
}

const char *get_class(int class)
{
	switch (class) {
	case 0:
		return "Control";
	case 1:
		return "Reserved";
	case 2:
		return "Measurement";
	case 3:
		return "Reserved";
	default:
		return "Unknown";
	}
}

#define OPT_TYPE_MASK 0x1f
#define OPT_CLASS_MASK 0x60
#define OPT_COPY_MASK 0x80

int dissector_ip_options(item *options, const u_char *buffer, size_t len)
{
	item *option, *type;

	int count = 0;

	while (len > 0) {
		int n = count++;
		int name_num = buffer[0] & OPT_TYPE_MASK;
		int class_num = (buffer[0] & OPT_CLASS_MASK) >> 5;
		const char *name = get_option(buffer[0] & OPT_TYPE_MASK);
		const char *copy = (buffer[0] & OPT_COPY_MASK) ? "Yes" : "No";
		const char *class = get_class(class_num);

		option = item_new_child_strf(options, "Option %d: %s", n, name);

		type = item_new_child_strf(option, "Type: (%d)", buffer[0]);
		item_new_child_strf(type, "Copy on fragmentation: %s", copy);
		item_new_child_strf(type, "Class: %s (%d)", class, class_num);
		item_new_child_strf(type, "Number: %s (%d)", name, name_num);

		buffer++;
		len--;

		if (name_num == 0)
			break;
		if (name_num == 1)
			continue;

		// TODO: Parse options

		// clang-format off
		item_set_strf(option, "Options %d: %s (%i bytes)", n, name, buffer[0]);
		item_new_child_strf(option, "Length: %d", buffer[0]);
		if (buffer[0] > 2)
			item_new_child_strf(option, "Data: %s", hexdumpa(buffer + 2, buffer[0] - 2));
		// clang-format on

		len -= buffer[1];
		buffer += buffer[1];
	}
	if (len < 0)
		return -1;

	return count;
}

int dissector_ipv4(struct packet_info *pi, const u_char *buffer, size_t len)
{
	item *item, *options;
	int length, id, off, sum;
	const char *src, *dst, *proto;

	struct iphdr *ip = (typeof(ip))buffer;

	buffer += sizeof(*ip);
	len -= sizeof(*ip);
	if (len < 0)
		return -1;

	length = ntohs(ip->tot_len);
	id = ntohs(ip->id);
	off = ntohs(ip->frag_off);
	sum = ntohs(ip->check);

	pi->dl_src.type = ADDRESS_TYPE_IP;
	pi->dl_src.len = 4;
	memcpy(pi->dl_src.ip, &ip->saddr, 4);
	pi->src = pi->dl_src;

	pi->dl_dst.type = ADDRESS_TYPE_IP;
	pi->dl_dst.len = 4;
	memcpy(pi->dl_dst.ip, &ip->daddr, 4);
	pi->dst = pi->dl_dst;

	src = strdupa(inet_ntoa(*(struct in_addr *)&ip->saddr));
	dst = strdupa(inet_ntoa(*(struct in_addr *)&ip->daddr));
	proto = get_protocol(ip->protocol);

	// clang-format off
	item = item_new_child_strf(pi->root, "IPv4, Src: %s, Dst: %s", src, dst);
	item_new_child_strf(item, "Version: %d", ip->version);
	item_new_child_strf(item, "Header Length: %d", ip->ihl);
	item_new_child_strf(item, "Differentiated Services Field: 0x%02x", ip->tos);
	item_new_child_strf(item, "Total Length: %d", length);
	item_new_child_strf(item, "Identification: 0x%04x", id);
	item_new_child_strf(item, "Flags: 0x%04x", off);
	item_new_child_strf(item, "Fragment Offset: %d", off & 0x1fff);
	item_new_child_strf(item, "Time to Live: %d", ip->ttl);
	item_new_child_strf(item, "Protocol: %s (%d)", proto, ip->protocol);
	// TODO: Check checksum
	item_new_child_strf(item, "Header Checksum: 0x%04x [Not verified]", sum);
	item_new_child_strf(item, "Source: %s", src);
	item_new_child_strf(item, "Destination: %s", dst);
	// clang-format on

	if (ip->ihl > 5) {
		int n;

		size_t size = (ip->ihl - 5) * 4;
		if (size > len)
			return -1;

		options =
			item_new_child_strf(item, "Options (%zu bytes)", size);
		n = dissector_ip_options(options, buffer, (ip->ihl - 5) * 4);
		if (n < 0)
			return -1;
		item_set_strf(options, "Options: %i (%zu bytes)", n, size);
	}

	return dissector_transport(ip->protocol, pi, buffer, len);
}
