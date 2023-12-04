#include <net/if_arp.h>
#include <netinet/ether.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include "dissector.h"
#include "utils/string.h"

const char *get_op(int opcode)
{
	switch (opcode) {
	case ARPOP_REQUEST:
		return "ARP Request";
	case ARPOP_REPLY:
		return "ARP Reply";
	case ARPOP_RREQUEST:
		return "RARP Request";
	case ARPOP_RREPLY:
		return "RARP Reply";
	case ARPOP_InREQUEST:
		return "InARP Request";
	case ARPOP_InREPLY:
		return "InARP Reply";
	case ARPOP_NAK:
		return "(ATM)ARP NAK";
	default:
		return "Unknown";
	}
}

const char *get_hrd(int hrd)
{
	switch (hrd) {
	/* ARP protocol HARDWARE identifiers. */
	case ARPHRD_ETHER:
		return "Ethernet";
	case ARPHRD_EETHER:
		return "Experimental Ethernet";
	case ARPHRD_AX25:
		return "AX.25";
	case ARPHRD_PRONET:
		return "PROnet token Ring";
	case ARPHRD_CHAOS:
		return "Chaos";
	case ARPHRD_IEEE802:
		return "IEEE 802";
	case ARPHRD_ARCNET:
		return "ARCnet";
	case ARPHRD_APPLETLK:
		return "APPLEtalk";
	case ARPHRD_DLCI:
		return "Frame Relay DLCI";
	case ARPHRD_ATM:
		return "ATM";
	case ARPHRD_METRICOM:
		return "Metricom STRIP (new IANA id)";
	case ARPHRD_IEEE1394:
		return "IEEE 1394 IPv4 - RFC 2734";
	case ARPHRD_EUI64:
		return "EUI-64";
	case ARPHRD_INFINIBAND:
		return "InfiniBand";

	/* Dummy types for non ARP hardware */
	case ARPHRD_SLIP:
		return "SLIP";
	case ARPHRD_CSLIP:
		return "CSLIP";
	case ARPHRD_SLIP6:
		return "SLIP6";
	case ARPHRD_CSLIP6:
		return "CSLIP6";
	case ARPHRD_RSRVD:
		return "RSRVD";
	case ARPHRD_ADAPT:
		return "ADAPT";
	case ARPHRD_ROSE:
		return "ROSE";
	case ARPHRD_X25:
		return "X25";
	case ARPHRD_HWX25:
		return "HWX25";
	case ARPHRD_PPP:
		return "PPP";
	case ARPHRD_CISCO:
		return "Cisco HDLC";
	case ARPHRD_LAPB:
		return "LAPB";
	case ARPHRD_DDCMP:
		return "DDCMP";
	case ARPHRD_RAWHDLC:
		return "Raw HDLC";
	case ARPHRD_RAWIP:
		return "Raw IP";

	case ARPHRD_TUNNEL:
		return "IPIP tunnel";
	case ARPHRD_TUNNEL6:
		return "IPIP6 tunnel";
	case ARPHRD_FRAD:
		return "Frame Relay Access Device";
	case ARPHRD_SKIP:
		return "SKIP vif";
	case ARPHRD_LOOPBACK:
		return "Loopback device";
	case ARPHRD_LOCALTLK:
		return "Localtalk device";
	case ARPHRD_FDDI:
		return "Fiber Distributed Data Interface";
	case ARPHRD_BIF:
		return "AP1000 BIF";
	case ARPHRD_SIT:
		return "sit0 device - IPv6-in-IPv4";
	case ARPHRD_IPDDP:
		return "IP-in-DDP tunnel";
	case ARPHRD_IPGRE:
		return "GRE over IP";
	case ARPHRD_PIMREG:
		return "PIMSM register interface";
	case ARPHRD_HIPPI:
		return "High Performance Parallel I'face";
	case ARPHRD_ASH:
		return "(Nexus Electronics) Ash";
	case ARPHRD_ECONET:
		return "Acorn Econet";
	case ARPHRD_IRDA:
		return "Linux-IrDA";
	case ARPHRD_FCPP:
		return "Point to point fibrechanel";
	case ARPHRD_FCAL:
		return "Fibrechanel arbitrated loop";
	case ARPHRD_FCPL:
		return "Fibrechanel public loop";
	case ARPHRD_FCFABRIC:
		return "Fibrechanel fabric";
	case ARPHRD_IEEE802_TR:
		return "Magic type ident for TR";
	case ARPHRD_IEEE80211:
		return "IEEE 802.11";
	case ARPHRD_IEEE80211_PRISM:
		return "IEEE 802.11 + Prism2 header";
	case ARPHRD_IEEE80211_RADIOTAP:
		return "IEEE 802.11 + radiotap header";
	case ARPHRD_IEEE802154:
		return "IEEE 802.15.4 header";
	case ARPHRD_IEEE802154_PHY:
		return "IEEE 802.15.4 PHY header";
	default:
		return "Unknown";
	}
}

const char *get_pro(int pro)
{
	switch (pro) {
	case ETHERTYPE_PUP:
		return " Xerox PUP";
	case ETHERTYPE_SPRITE:
		return " Sprite";
	case ETHERTYPE_IP:
		return " IP";
	case ETHERTYPE_ARP:
		return " Address resolution";
	case ETHERTYPE_REVARP:
		return " Reverse ARP";
	case ETHERTYPE_AT:
		return " AppleTalk protocol";
	case ETHERTYPE_AARP:
		return " AppleTalk ARP";
	case ETHERTYPE_VLAN:
		return " IEEE 802.1Q VLAN tagging";
	case ETHERTYPE_IPX:
		return " IPX";
	case ETHERTYPE_IPV6:
		return " IP protocol version 6";
	case ETHERTYPE_LOOPBACK:
		return " used to test interfaces";
	default:
		return "Unknown";
	}
}

int dissector_arp(struct packet_info *pi, const u_char *buffer, size_t len)
{
	unsigned short hrd, pro, op;
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	char src_mac[ETHER_ADDRSTRLEN], dst_mac[ETHER_ADDRSTRLEN];

	item *items = item_add(pi->root);

	if (len < sizeof(struct arphdr)) {
		warnx("Malformed ARP header");
		goto malformed;
	}

	struct arphdr *arp = (struct arphdr *)buffer;

	buffer += sizeof(struct arphdr);
	len -= sizeof(struct arphdr);

	hrd = ntohs(arp->ar_hrd);
	pro = ntohs(arp->ar_pro);
	op = ntohs(arp->ar_op);

	// clang-format off
	item_set_strf(items, "Address Resolution Protocol: %s (%d)", get_op(op), op);
	item_add_strf(items, "Hardware type: %s (%d)", get_hrd(hrd), hrd);
	item_add_strf(items, "Protocol type: %s (0x%04x)", get_pro(pro), pro);
	item_add_strf(items, "Hardware size: %d", arp->ar_hln);
	item_add_strf(items, "Protocol size: %d", arp->ar_pln);
	item_add_strf(items, "Opcode: %s (%d)", get_op(op), op);
	// clang-format on

	if (len < arp->ar_hln * 2 + arp->ar_pln * 2) {
		warnx("Truncated address");
		item_add_strf(items, "[Truncated address]");
		goto malformed;
	}

	if (hrd != ARPHRD_ETHER || pro != ETHERTYPE_IP)
		return 0;

	if (arp->ar_hln != 6) {
		warnx("Malformed hardware address size");
		item_add_strf(items, "[Malformed hardware address size]");
		goto malformed;
	}
	if (arp->ar_pln != 4) {
		warnx("Malformed ip address size");
		item_add_strf(items, "[Malformed ip address size]");
		goto malformed;
	}

	pi->dl_src.type = ADDRESS_TYPE_MAC;
	pi->dl_src.len = 6;
	memcpy(pi->dl_src.mac, buffer, 6);
	pi->src = pi->dl_src;

	pi->dl_dst.type = ADDRESS_TYPE_MAC;
	pi->dl_dst.len = 6;
	memcpy(pi->dl_dst.mac, buffer + arp->ar_hln + arp->ar_pln, 6);
	pi->src = pi->dl_dst;

	if (inet_ntop(AF_INET, buffer + arp->ar_hln, src, sizeof(src)) == NULL)
		err(EXIT_FAILURE, "inet_ntop");

	if (inet_ntop(AF_INET, buffer + arp->ar_hln * 2 + arp->ar_pln, dst,
		      sizeof(dst)) == NULL)
		err(EXIT_FAILURE, "inet_ntop");

	if (ether_ntoa_r((const void *)buffer, src_mac) == NULL)
		err(EXIT_FAILURE, "inet_ntop");

	if (ether_ntoa_r((const void *)(buffer + arp->ar_hln + arp->ar_pln),
			 dst_mac) == NULL)
		err(EXIT_FAILURE, "inet_ntop");

	item_add_strf(items, "Sender MAC address: %s", src_mac);
	item_add_strf(items, "Sender IP address: %s", src);
	item_add_strf(items, "Target MAC address: %s", dst_mac);
	item_add_strf(items, "Target IP address: %s", dst);
	return 0;

malformed:
	item_set_strf(items, "Address Resolution Protocol [Malformed]");
	return -1;
}
