#include <netinet/ether.h>
#include <pcap/sll.h>
#include <string.h>
#include <err.h>

#include "dissector.h"
#include "item.h"
#include "utils/string.h"

const char *get_eth_type(ushort type)
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

int dissector_ethertype(ushort type, struct packet_info *pi,
			const u_char *buffer, size_t len)
{
	if (type == ETHERTYPE_IP)
		return dissector_ipv4(pi, buffer, len);
	else if (type == ETHERTYPE_IPV6)
		return dissector_ipv6(pi, buffer, len);
	else if (type == ETHERTYPE_ARP)
		return dissector_arp(pi, buffer, len);
	return 0;
}

int dissector_ethernet(struct packet_info *pi, const u_char *buffer, size_t len)
{
	item *item;
	ushort type;
	char *src, *dst;

	struct ether_header *eth = (typeof(eth))buffer;

	buffer += sizeof(*eth);
	len -= sizeof(*eth);
	if (len < 0)
		return -1;

	type = ntohs(eth->ether_type);

	pi->dl_src.type = ADDRESS_TYPE_MAC;
	pi->dl_src.len = 6;
	memcpy(pi->dl_src.mac, eth->ether_shost, 6);
	pi->src = pi->dl_src;

	pi->dl_dst.type = ADDRESS_TYPE_MAC;
	pi->dl_dst.len = 6;
	memcpy(pi->dl_dst.mac, eth->ether_dhost, 6);
	pi->src = pi->dl_dst;

	src = strdupa(ether_ntoa((const struct ether_addr *)eth->ether_shost));
	dst = strdupa(ether_ntoa((const struct ether_addr *)eth->ether_dhost));

	item = item_new_child_strf(pi->root, "Ethernet II, Src: %s, Dst: %s",
				   src, dst);

	item_new_child_strf(item, "Destination: %s", dst);
	item_new_child_strf(item, "Source: %s", src);
	item_new_child_strf(item, "Type: %s (%hu)", get_eth_type(type), type);
	item_new_child_strf(item, "Payload: %lu bytes", len - sizeof(*eth));

	return dissector_ethertype(type, pi, buffer, len);
}

const char *get_sll_type(uint16_t type)
{
	if (type == LINUX_SLL_HOST)
		return "Unicast to us";
	else if (type == LINUX_SLL_BROADCAST)
		return "Broadcast to us";
	else if (type == LINUX_SLL_MULTICAST)
		return "Multicast";
	else if (type == LINUX_SLL_OTHERHOST)
		return "Unicast to another host";
	else if (type == LINUX_SLL_OUTGOING)
		return "Send by us";
	else
		return "Unknown";
}

int dissector_linux_sll(struct packet_info *pi, const u_char *buffer,
			size_t len)
{
	uint16_t pkttype, hatype, halen, protocol;
	struct protoent *proto;
	item *item;

	struct sll_header *sll = (typeof(sll))buffer;

	buffer += sizeof(*sll);
	len -= sizeof(*sll);
	if (len < 0)
		return -1;

	pkttype = ntohs(sll->sll_pkttype);
	hatype = ntohs(sll->sll_hatype);
	halen = ntohs(sll->sll_halen);
	protocol = ntohs(sll->sll_protocol);

	if (halen < ADDRESS_LEN) {
		if (halen == 0)
			pi->dl_src.type = ADDRESS_TYPE_NONE;
		else
			pi->dl_src.type = ADDRESS_TYPE_MAC;

		pi->dl_src.len = halen;
		memcpy(pi->dl_src.mac, sll->sll_addr, halen);
		pi->src = pi->dl_src;
	} else {
		warnx("Invalid address length: %hu", halen);
	}

	item = item_new_child_strf(pi->root, "Linux cooked capture");

	item_new_child_strf(item, "Packet type: %s (%hu)",
			    get_sll_type(pkttype), pkttype);
	item_new_child_strf(item, "Link layer address type: %hu", hatype);
	item_new_child_strf(item, "Link layer address length: %hu", halen);

	if (halen == 6) {
		item_new_child_strf(
			item, "Source: %s",
			ether_ntoa((const struct ether_addr *)sll->sll_addr));
	} else {
		item_new_child_strf(item, "Source: Unknown");
	}
	if ((proto = getprotobynumber(protocol)) != NULL) {
		item_new_child_strf(item, "Protocol: %s (%hu)", proto->p_name,
				    protocol);
	} else {
		item_new_child_strf(item, "Protocol: %hu", protocol);
	}

	return dissector_ethertype(protocol, pi, buffer, len);
}
