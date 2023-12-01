#include "packet.h"
#include <netinet/in.h>
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

const char *get_opt_class(int class)
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

int dissector_ip_options(item *items, const u_char *buffer, size_t len)
{
	item *options = item_new_child_strf(items, "Options");
	int count = 0;
	int only_opt = 0; // 0 = none, -1 multiple, >0 = only one

	while (len > 0) {
		int i = count++;

		int num = buffer[0] & IPOPT_NUMBER_MASK;
		int class = buffer[0] & IPOPT_CLASS_MASK;
		int copy = IPOPT_COPIED(buffer[0]);

		// clang-format off
		item *option = item_new_child_strf(options, "Option %d: %s", i, get_option(num));

		item *type = item_new_child_strf(option, "Type: (%d)", buffer[0]);
		item_new_child_strf(type, "Copy on fragmentation: %s (0x%02x)", copy ? "Yes" : "No", copy);
		item_new_child_strf(type, "Class: %s (0x%02x)", get_opt_class(class), class);
		item_new_child_strf(type, "Number: %s (0x%02x)", get_option(num), num);
		// clang-format on

		buffer++;
		len--;

		if (num == IPOPT_EOL)
			break;
		if (num == IPOPT_NOP)
			continue;

		if (only_opt == 0)
			only_opt = num;
		else if (only_opt != num)
			only_opt = -1;

		if (buffer[0] > MAX_IPOPTLEN)
			return -1;
		// TODO: Parse options

		// clang-format off
		item_set_strf(option, "Option %d: %s (%i bytes)", i, get_option(num), buffer[0]);
		item_new_child_strf(option, "Length: %d", buffer[0]);
		if (buffer[0] > 2)
			item_new_child_strf(option, "Data: %s", hexdumpa(buffer + 2, buffer[0] - 2));
		// clang-format on

		len -= buffer[1];
		buffer += buffer[1];
	}
	if (len < 0)
		return -1;

	if (count == 0)
		item_set_strf(options, "Options: None");
	else if (only_opt > 0)
		item_set_strf(options, "Option: %s", get_option(only_opt));
	else
		item_set_strf(options, "Options: %d", count);
	return 0;
}

int dissector_ipv4(struct packet_info *pi, const u_char *buffer, size_t len)
{
	int length, id, off, sum;
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	const char *proto;

	struct iphdr *ip = (typeof(ip))buffer;
	item *item = item_new_child_strf(pi->root, "IPv4");

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

	if (inet_ntop(AF_INET, &ip->saddr, src, INET_ADDRSTRLEN) == NULL) {
		warn("inet_ntop");
		return -1;
	}
	if (inet_ntop(AF_INET, &ip->daddr, dst, INET_ADDRSTRLEN) == NULL) {
		warn("inet_ntop");
		return -1;
	}

	proto = get_protocol(ip->protocol, 0);

	// clang-format off
	item_set_strf(item, "IPv4, Src: %s, Dst: %s", src, dst);
	item_new_child_strf(item, "Version: %d", ip->version);
	item_new_child_strf(item, "Header Length: %d", ip->ihl);
	item_new_child_strf(item, "Differentiated Services Field: 0x%02x", ip->tos);
	item_new_child_strf(item, "Total Length: %d", length);
	item_new_child_strf(item, "Identification: 0x%04x", id);
	item_new_child_strf(item, "Flags: 0x%04x", off);
	item_new_child_strf(item, "Fragment Offset: %d", off & 0x1fff);
	item_new_child_strf(item, "Time to Live: %d", ip->ttl);
	item_new_child_strf(item, "Protocol: %s (%d)", proto, ip->protocol);
	item_new_child_strf(item, "Header Checksum: 0x%04x [Not verified]", sum); // TODO
	item_new_child_strf(item, "Source: %s", src);
	item_new_child_strf(item, "Destination: %s", dst);
	// clang-format on

	if (ip->ihl > 5) {
		size_t size = (ip->ihl - 5) * 4;
		if (size > len)
			goto malformed;
		if (dissector_ip_options(item, buffer, size) < 0)
			goto malformed;
	}

	return dissector_transport(ip->protocol, pi, buffer, len);

malformed:
	item_set_strf(item, "Malformed IPv4");
	return -1;
}

int dissector_ipv6(struct packet_info *pi, const u_char *buffer, size_t len)
{
	item *item = item_new_child_strf(pi->root, "IPv6");
	uint32_t flow;
	uint16_t length;
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	const char *proto;

	struct ip6_hdr *ip = (typeof(ip))buffer;

	buffer += sizeof(*ip);
	len -= sizeof(*ip);

	if (len < 0)
		goto malformed;

	flow = ntohl(ip->ip6_flow);
	length = ntohs(ip->ip6_plen);

	pi->dl_src.type = ADDRESS_TYPE_IP6;
	pi->dl_src.len = 16;
	memcpy(pi->dl_src.ip6, &ip->ip6_src, 16);
	pi->src = pi->dl_src;

	pi->dl_dst.type = ADDRESS_TYPE_IP6;
	pi->dl_dst.len = 16;
	memcpy(pi->dl_dst.ip6, &ip->ip6_dst, 16);
	pi->dl_dst = pi->dl_dst;

	if (inet_ntop(AF_INET6, &ip->ip6_src, src, sizeof(src)) == NULL)
		return -1;
	if (inet_ntop(AF_INET6, &ip->ip6_dst, dst, sizeof(dst)) == NULL)
		return -1;

	proto = get_protocol(ip->ip6_nxt, 1);

	// clang-format off
	item_set_strf(item, "IPv6, Src: %s, Dst: %s", src, dst);
	item_new_child_strf(item, "Version: %d", ip->ip6_vfc >> 4);
	item_new_child_strf(item, "Traffic Class: 0x%02x", ip->ip6_vfc & 0x0f);
	item_new_child_strf(item, "Flow Label: 0x%05x", flow & 0x000fffff);
	item_new_child_strf(item, "Payload Length: %d", length);
	item_new_child_strf(item, "Hop Limit: %d", ip->ip6_hlim);
	item_new_child_strf(item, "Next Header: (%s) %d", proto, ip->ip6_nxt);
	// clang-format on

	if (length > len)
		goto malformed;

	return dissector_transport(ip->ip6_nxt, pi, buffer, length);

malformed:
	item_set_strf(item, "Malformed IPv6");
	return -1;
}
