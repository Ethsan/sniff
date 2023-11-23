#pragma once

#include <sys/time.h>
#include <sys/types.h>

#include "item_list.h"

enum address_type {
	ADDRESS_TYPE_NONE,
	ADDRESS_TYPE_MAC,
	ADDRESS_TYPE_IP,
	ADDRESS_TYPE_IP6,
};

struct address {
	enum address_type type;
	int len;

	const void *addr;
};

enum packet_type {
	PACKET_TYPE_NONE,

	PACKET_TYPE_ETHERNET,
	PACKET_TYPE_IPV4,
	PACKET_TYPE_IPV6,
	PACKET_TYPE_TCP,
	PACKET_TYPE_UDP,
	PACKET_TYPE_ICMP,
	PACKET_TYPE_ICMP6,
	PACKET_TYPE_DHCP,
	PACKET_TYPE_DNS,
	PACKET_TYPE_SMTP,
	PACKET_TYPE_POP,
	PACKET_TYPE_IMAP,
	PACKET_TYPE_HTTP,
	PACKET_TYPE_FTP,
	PACKET_TYPE_HTTPS,
	PACKET_TYPE_SSH,
	PACKET_TYPE_TELNET,
	PACKET_TYPE_SCTP,
	PACKET_TYPE_LDAP,
};

struct packet_info {
	struct timeval ts;
	int caplen;
	int len;

	struct address dl_src;
	struct address dl_dst;
	struct address net_src;
	struct address net_dst;
	struct address src;
	struct address dst;

	uint port_src;
	uint port_dst;

	enum packet_type type;
	char *summary;

	item_list *data;
};
