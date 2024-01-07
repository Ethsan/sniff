#include <netinet/tcp.h>
#include <stddef.h>
#include <stdlib.h>
#include <err.h>

#include "dissector/dissector.h"
#include "utils/tcp_port.h"
#include "utils/string.h"

#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_NS 0x100
#define TH_RES1 0x0200
#define TH_RES2 0x0400
#define TH_RES3 0x0800

#define IS_FIN(x) ((x & TH_FIN) == TH_FIN)
#define IS_SYN(x) ((x & TH_SYN) == TH_SYN)
#define IS_RST(x) ((x & TH_RST) == TH_RST)
#define IS_PSH(x) ((x & TH_PUSH) == TH_PUSH)
#define IS_ACK(x) ((x & TH_ACK) == TH_ACK)
#define IS_URG(x) ((x & TH_URG) == TH_URG)
#define IS_ECE(x) ((x & TH_ECE) == TH_ECE)
#define IS_CWR(x) ((x & TH_CWR) == TH_CWR)
#define IS_NS(x) ((x & TH_NS) == TH_NS)
#define IS_RES1(x) ((x & TH_RES1) == TH_RES1)
#define IS_RES2(x) ((x & TH_RES2) == TH_RES2)
#define IS_RES3(x) ((x & TH_RES3) == TH_RES3)

#define IS_RES(x) (IS_RES1(x) || IS_RES2(x) || IS_RES3(x))

#define IS_ONLY_ONE(x)                                                \
	((IS_FIN(x) + IS_SYN(x) + IS_RST(x) + IS_PSH(x) + IS_ACK(x) + \
	  IS_URG(x)) == 1)

const char *get_flag(unsigned char flag)
{
	switch (flag & 0x3f) {
	case TH_FIN:
		return "FIN";
	case TH_SYN:
		return "SYN";
	case TH_RST:
		return "RST";
	case TH_PUSH:
		return "PSH";
	case TH_ACK:
		return "ACK";
	case TH_URG:
		return "URG";
	case TH_ECE:
		return "ECE";
	case TH_CWR:
		return "CWR";
	case TH_NS:
		return "ECN/NS";
	default:
		return "Unknown";
	}
}

// https://www.iana.org/assignments/tcp-parameters/tcp-parameters-1.csv
const char *get_opt_code(unsigned char code)
{
	switch (code) {
	case 0:
		return "End of Option List";
	case 1:
		return "No-Operation";
	case 2:
		return "Maximum Segment Size";
	case 3:
		return "Window Scale";
	case 4:
		return "SACK Permitted";
	case 5:
		return "SACK";
	case 6:
		return "Echo";
	case 7:
		return "Echo Reply";
	case 8:
		return "Timestamps";
	case 9:
		return "Partial Order Connection Permitted";
	case 10:
		return "Partial Order Service Profile";
	case 11:
		return "CC";
	case 12:
		return "CC.NEW";
	case 13:
		return "CC.ECHO";
	case 14:
		return "TCP Alternate Checksum Request";
	case 15:
		return "TCP Alternate Checksum Data";
	case 16:
		return "Skeeter";
	case 17:
		return "Bubba";
	case 18:
		return "Trailer Checksum Option";
	case 19:
		return "MD5 Signature Option";
	case 20:
		return "SCPS Capabilities";
	case 21:
		return "Selective Negative Acknowledgements";
	case 22:
		return "Record Boundaries";
	case 23:
		return "Corruption experienced";
	case 24:
		return "SNAP";
	case 25:
		return "Unassigned";
	case 26:
		return "TCP Compression Filter";
	case 27:
		return "Quick-Start Response";
	case 28:
		return "User Timeout Option";
	case 29:
		return "TCP Authentication Option";
	case 30:
		return "Multipath TCP";
	case 69:
		return "Encryption Negotiation";
	case 172:
		return "Accurate ECN Order 0";
	case 173:
		return "Reserved";
	case 174:
		return "Accurate ECN Order 1";
	case 253:
		return "RFC3692-style Experiment 1";
	case 254:
		return "RFC3692-style Experiment 2";
	default:
		return "Unknown";
	}
}

static int dissector_payload(struct packet_info *pi, const u_char *buffer,
			     size_t len)
{
	int src = pi->port_src, dst = pi->port_dst;

	if (src == 80 || dst == 80) // HTTP
		return dissector_http(pi, buffer, len);
	else if (src == 53 || dst == 53) // DNS
		return dissector_dns(pi, buffer, len);
	else if (src == 67 || dst == 67 || src == 68 || dst == 68) // DHCP
		return dissector_bootp(pi, buffer, len);
	else if (src == 20 || dst == 20 || src == 21 || dst == 21) // FTP
		return dissector_ftp(pi, buffer, len);
	else if (src == 23 || dst == 23) // Telnet
		return dissector_telnet(pi, buffer, len);
	else if (src == 22 || dst == 22) // SSH
		return dissector_ssh(pi, buffer, len);
	else if (src == 25 || dst == 25) // SMTP
		return dissector_smtp(pi, buffer, len);
	else if (src == 36412 || dst == 36412) // SFTP
		return dissector_sctp(pi, buffer, len);
	else if (src == 110 || dst == 110) // POP3
		return dissector_pop(pi, buffer, len);
	else if (src == 143 || dst == 143) // IMAP
		return dissector_imap(pi, buffer, len);
	return 0;
}

int dissect_opt(item *items, const u_char *buffer, size_t len)
{
	item *item, *opt = item_add(items);
	int count = 0, only_opt = 0; // 0 = none, -1 multiple, >0 = only one

	while (len > 0) {
		unsigned char code, length;

		length = 1;
		code = buffer[0];

		if (code == 0) // End of Option List
			break;

		// clang-format off
		item = item_add_strf(opt, "Option #%d, %s (%d)", count, get_opt_code(code), code);
		item_add_strf(item, "Kind: %d (%s)", code, get_opt_code(code));
		// clang-format on

		if (code == 1) // No-Operation
			goto next;
		if (len < 2)
			goto truncated;

		length = buffer[1];
		if (len < length)
			goto truncated;

		if (length > 2)
			item_add_strf(item, "Value: %s",
				      hexdumpa(&buffer[3], length - 2));

		if (only_opt == 0)
			only_opt = code;
		else
			only_opt = -1;

next:
		buffer += length;
		len -= length;
		count++;
	}
	if (only_opt > 0)
		item_set_strf(opt, "Options (%s)", get_opt_code(only_opt));
	else
		item_set_str(opt, "Options");

	return 0;

truncated:
	item_set_str(opt, "Options [Truncated]");
	return -1;
}

int dissector_tcp(struct packet_info *pi, const u_char *buffer, size_t len)
{
	uint16_t src, dst, win, sum, urg;
	uint32_t seq, ack;
	uint16_t f;
	item *flags, *items = item_add_str(pi->root, "TCP");

	if (len < sizeof(struct tcphdr)) {
		warnx("Malformed TCP header");
		item_set_str(items, "TCP [Malformed]");
		return -1;
	}

	struct tcphdr *tcp = (struct tcphdr *)buffer;

	src = ntohs(tcp->source);
	dst = ntohs(tcp->dest);
	win = ntohs(tcp->window);
	sum = ntohs(tcp->check);
	urg = ntohs(tcp->urg_ptr);

	seq = ntohl(tcp->seq);
	ack = ntohl(tcp->ack_seq);

	f = tcp->th_flags + (tcp->th_x2 << 8);

	pi->port_dst = dst;
	pi->port_src = src;

	// clang-format off
	item_set_strf(items, "Transmission Control Protocol, Src Port: %d, Dst Port: %d, Seq: %u, Ack: %u, Len: %zu", src, dst, seq, ack, len - tcp->doff * 4);
	item_add_strf(items, "Source Port: %s (%d)", get_tcp_port(src), src);
	item_add_strf(items, "Destination Port: %s (%d)", get_tcp_port(dst), dst);
	item_add_strf(items, "Sequence number: %u", seq);
	item_add_strf(items, "Acknowledgment number: %u", ack);
	item_add_strf(items, "Header Length: %d bytes", tcp->doff * 4);
	flags = item_add_strf(items, "Flags: 0x%02x", f);
	item_add_strf(items, "Window size value: %d", win);
	item_add_strf(items, "Checksum: 0x%04x", sum);
	item_add_strf(items, "Urgent pointer: %d", urg);

	if (IS_ONLY_ONE(f))
		flags = item_add_strf(items, "Flags: 0x%02x (%s)", f, get_flag(f));
	item_add_strf(flags, "%c%c%c. .... .... = Reserved: %s", IS_RES1(f) ? '1' : '0', IS_RES2(f) ? '1' : '0', IS_RES3(f) ? '1' : '0', IS_RES(f) ? "Set" : "Not set");
	item_add_strf(flags, "...%c .... .... = ECN / Nonce: %s", IS_NS(f) ? '1' : '0', IS_NS(f) ? "Set" : "Not set");
	item_add_strf(flags, ".... %c... .... = Congestion Window Reduced (CWR): %s", IS_CWR(f) ? '1' : '0', IS_CWR(f) ? "Set" : "Not set");
	item_add_strf(flags, ".... .%c.. .... = ECN-Echo: %s", IS_ECE(f) ? '1' : '0', IS_ECE(f) ? "Set" : "Not set");
	item_add_strf(flags, ".... ..%c. .... = Urgent: %s", IS_URG(f) ? '1' : '0', IS_URG(f) ? "Set" : "Not set");
	item_add_strf(flags, ".... ...%c .... = Acknowledgment: %s", IS_ACK(f) ? '1' : '0', IS_ACK(f) ? "Set" : "Not set");
	item_add_strf(flags, ".... .... %c... = Push: %s", IS_PSH(f) ? '1' : '0', IS_PSH(f) ? "Set" : "Not set");
	item_add_strf(flags, ".... .... .%c.. = Reset: %s", IS_RST(f) ? '1' : '0', IS_RST(f) ? "Set" : "Not set");
	item_add_strf(flags, ".... .... ..%c. = Syn: %s", IS_SYN(f) ? '1' : '0', IS_SYN(f) ? "Set" : "Not set");
	item_add_strf(flags, ".... .... ...%c = Fin: %s", IS_FIN(f) ? '1' : '0', IS_FIN(f) ? "Set" : "Not set");
	// clang-format on

	int opt_len = tcp->doff * 4 - sizeof(struct tcphdr);

	if (opt_len < 0) {
		item_add_str(items, "[Bad Header Length]");
		goto malformed;
	}

	if (opt_len > 0 &&
	    dissect_opt(items, buffer + sizeof(struct tcphdr), opt_len) < 0)
		goto malformed;

	buffer += tcp->doff * 4;
	len -= tcp->doff * 4;

	if (len > 0)
		return dissector_payload(pi, buffer, len);

	return 0;

malformed:
	item_set_str(items, "TCP [Malformed]");
	return -1;
}
