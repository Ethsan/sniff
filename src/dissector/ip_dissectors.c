#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stddef.h>
#include <string.h>

#include "dissector.h"
#include "utils/string.h"

const char *get_protocol(int protocol, int is_ipv6)
{
	switch (protocol) {
	case IPPROTO_IP:
		if (is_ipv6)
			return "IPv6 Hop-by-Hop Options";
		else
			return "Dummy";
	case IPPROTO_ICMP:
		return "Internet Control Message Protocol (ICMP)";
	case IPPROTO_IGMP:
		return "Internet Group Management Protocol (IGMP)";
	case IPPROTO_IPIP:
		return "IPIP tunnels";
	case IPPROTO_TCP:
		return "Transmission Control Protocol (TCP)";
	case IPPROTO_EGP:
		return "Exterior Gateway Protocol (EGP)";
	case IPPROTO_PUP:
		return "PUP Protocol";
	case IPPROTO_UDP:
		return "User Datagram Protocol (UDP)";
	case IPPROTO_IDP:
		return "XNS IDP protocol";
	case IPPROTO_TP:
		return "SO Transport Protocol Class 4";
	case IPPROTO_DCCP:
		return "Datagram Congestion Control Protocol";
	case IPPROTO_IPV6:
		return "IPv6 header";
	case IPPROTO_RSVP:
		return "Reservation Protocol";
	case IPPROTO_GRE:
		return "General Routing Encapsulation";
	case IPPROTO_ESP:
		return "encapsulating security payload";
	case IPPROTO_AH:
		return "authentication header";
	case IPPROTO_MTP:
		return "Multicast Transport Protocol";
	case IPPROTO_BEETPH:
		return "IP option pseudo header for BEET";
	case IPPROTO_ENCAP:
		return "Encapsulation Header";
	case IPPROTO_PIM:
		return "Protocol Independent Multicast";
	case IPPROTO_COMP:
		return "Compression Header Protocol";
	case IPPROTO_L2TP:
		return "Layer 2 Tunnelling Protocol";
	case IPPROTO_SCTP:
		return "Stream Control Transmission Protocol";
	case IPPROTO_UDPLITE:
		return "UDP-Lite protocol";
	case IPPROTO_MPLS:
		return "MPLS in IP";
	case IPPROTO_ETHERNET:
		return "Ethernet-within-IPv6 Encapsulation";
	case IPPROTO_RAW:
		return "Raw IP packets";
	case IPPROTO_MPTCP:
		return "Multipath TCP connection";
	}

	if (!is_ipv6)
		return "Unknown";

	switch (protocol) {
	case IPPROTO_ROUTING:
		return "IPv6 routing header";
	case IPPROTO_FRAGMENT:
		return "IPv6 fragmentation header";
	case IPPROTO_ICMPV6:
		return "ICMPv6";
	case IPPROTO_NONE:
		return "IPv6 no next header";
	case IPPROTO_DSTOPTS:
		return "IPv6 destination options";
	case IPPROTO_MH:
		return "IPv6 mobility header";
	}

	return "Unknown";
}

int dissector_transport(int protocol, struct packet_info *pi,
			const u_char *buffer, size_t len)
{
	switch (protocol) {
	case IPPROTO_IP:
		return dissector_ipv4(pi, buffer, len);
	case IPPROTO_ICMP:
		return dissector_icmp(pi, buffer, len);
	case IPPROTO_TCP:
		return dissector_tcp(pi, buffer, len);
	case IPPROTO_UDP:
		return dissector_udp(pi, buffer, len);
	case IPPROTO_IPV6:
		return dissector_ipv6(pi, buffer, len);
	case IPPROTO_SCTP:
		return dissector_sctp(pi, buffer, len);
	case IPPROTO_ETHERNET:
		return dissector_ethernet(pi, buffer, len);
	}
	return 0;
}

const char *get_option(int type)
{
	switch (type) {
	case IPOPT_EOL:
		return "End of Options List (EOL)";
	case IPOPT_NOP:
		return "No Operation (NOP)";
	case IPOPT_RR:
		return "Record Route (RR)";
	case IPOPT_TS:
		return "Internet Timestamp (TS)";
	case 3:
	case IPOPT_LSRR:
		return "Loose Source Route (LSR)";
	case IPOPT_SATID:
		return "Satnet ID (SATID)";
	case IPOPT_SSRR:
		return "Strict Source Route (SSR)";
	case IPOPT_RA:
		return "Router Alert (RA)";
	default:
		return "Unknown";
	}
}

const char *get_class(int class)
{
	switch (class) {
	case IPOPT_CONTROL:
		return "Control";
	case IPOPT_RESERVED1:
	case IPOPT_RESERVED2:
		return "Reserved";
	case IPOPT_MEASUREMENT:
		return "Measurement";
	default:
		return "Unknown";
	}
}

int dissector_ip_options(item *options, const u_char *buffer, size_t len)
{
	item *option, *type;

	int count = 0;

	while (len > 0) {
		int i = count++;

		int num = buffer[0] & IPOPT_NUMBER_MASK;
		int class = buffer[0] & IPOPT_CLASS_MASK;
		int copy = IPOPT_COPIED(buffer[0]);

		const char *num_s = get_option(num);
		const char *copy_s = copy ? "Yes" : "No";
		const char *class_s = get_class(class);

		// clang-format off
		option = item_new_child_strf(options, "Option %d: %s", i, num_s);

		type = item_new_child_strf(option, "Type: (%d)", buffer[0]);
		item_new_child_strf(type, "Copy on fragmentation: %s (0x%02x)", copy_s, copy);
		item_new_child_strf(type, "Class: %s (0x%02x)", class_s, class);
		item_new_child_strf(type, "Number: %s (0x%02x)", num_s, num);
		// clang-format on

		buffer++;
		len--;

		if (num == IPOPT_EOL)
			break;
		if (num == IPOPT_NOP)
			continue;
		if (buffer[0] > MAX_IPOPTLEN)
			return -1;
		// TODO: Parse options

		// clang-format off
		item_set_strf(option, "Options %d: %s (%i bytes)", i, num_s, buffer[0]);
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
	proto = get_protocol(ip->protocol, 0);

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

int dissector_ipv6(struct packet_info *pi, const u_char *buffer, size_t len)
{
	return 0;
}
