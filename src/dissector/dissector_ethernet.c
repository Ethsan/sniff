#include <netinet/ether.h>
#include <stdint.h>
#include <string.h>

#include "dissector.h"
#include "item_list.h"

const char *get_ethernet_type_str(ushort type)
{
	if (type == ETHERTYPE_PUP)
		return "PUP";
	else if (type == ETHERTYPE_IP)
		return "IP";
	else if (type == ETHERTYPE_ARP)
		return "ARP";
	else if (type == ETHERTYPE_REVARP)
		return "Reverse ARP";
	else if (type == ETHERTYPE_VLAN)
		return "IEEE 802.1Q VLAN tagging";
	else if (type == ETHERTYPE_IPV6)
		return "IPv6";
	else if (type == ETHERTYPE_LOOPBACK)
		return "Loopback";
	return "Unknown";
}

int dissector_ethernet(struct packet_info *pi, const u_char *buffer, int len)
{
	struct item *item;
	struct item_list *sub;

	struct ether_header *eth = (typeof(eth))buffer;
	ushort type = ntohs(eth->ether_type);

	pi->dl_src.type = ADDRESS_TYPE_MAC;
	pi->dl_src.len = 6;
	memcpy(pi->dl_src.mac, eth->ether_shost, 6);
	pi->src = pi->dl_src;

	pi->dl_dst.type = ADDRESS_TYPE_MAC;
	pi->dl_dst.len = 6;
	memcpy(pi->dl_dst.mac, eth->ether_dhost, 6);
	pi->src = pi->dl_dst;

	// clang-format off
	item = item_list_add_strf(
		pi->items,
		"Ethernet II, Src: %s, Dst: %s",
		ether_ntoa((const struct ether_addr *)eth->ether_shost),
		ether_ntoa((const struct ether_addr *)eth->ether_dhost)
	);

	sub = item_add_sublist(item);
	item_list_add_strf(
		sub,
		"Destination: %s",
		ether_ntoa((const struct ether_addr *)eth->ether_dhost)
	);
	item_list_add_strf(
		sub,
		"Source: %s",
		ether_ntoa((const struct ether_addr *)eth->ether_shost)
	);
	item_list_add_strf(
		sub,
		"Type: %s (%hu)",
		get_ethernet_type_str(type), type
	);
	item_list_add_strf(
		sub,
		"Payload: %lu bytes",
		len - sizeof(*eth)
	);
	// clang-format on

	if (type == ETHERTYPE_IP)
		return dissector_ipv4(pi, buffer + sizeof(*eth),
				      len - sizeof(*eth));
	else if (type == ETHERTYPE_IPV6)
		return dissector_ipv6(pi, buffer + sizeof(*eth),
				      len - sizeof(*eth));
	else if (type == ETHERTYPE_ARP)
		return dissector_arp(pi, buffer + sizeof(*eth),
				     len - sizeof(*eth));
	return 0;
}
