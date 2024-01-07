#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>

#include "dissector.h"
#include "item.h"

#define __packed __attribute__((packed))

struct __packed dns_header {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};

struct __packed dns_question {
	uint16_t type;
	uint16_t class;
};

struct __packed dns_rr {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
};

int handle_compressed_label(const u_char *buffer, const u_char *start, int len,
			    char *label);

int parse_label(const u_char *buffer, const u_char *start, int len, char *label)
{
	const u_char *ptr = buffer;
	int str_len = 0;

	while (*buffer != 0) {
		if ((*buffer & 0xC0) == 0xC0) // Check for compression
			return handle_compressed_label(buffer, start, len,
						       label);
		int label_len = *buffer++; // Get the length of the label
		len--;
		if (label_len > len) {
			return -1;
		}

		memcpy(label + str_len, buffer, label_len); // Copy the label

		// Update the string length, buffer, and length
		str_len += label_len;
		buffer += label_len;
		len -= label_len;

		// Add a period if there are more labels
		if (*buffer != 0) {
			label[str_len++] = '.';
		}
	}
	label[str_len] = '\0';
	return buffer - ptr + 1; // Return the number of bytes consumed
}

int handle_compressed_label(const u_char *buffer, const u_char *start, int len,
			    char *label)
{
	if (len < 2)
		return -1;

	uint16_t offset = ntohs(*((uint16_t *)buffer)) & 0x3FFF;
	if (offset >= buffer - start) // Check for loops
		return -1;

	// Recurse at the offset
	return parse_label(start + offset, start, len - 2, label);
}

void parse_rr_data(item *rr_info, const u_char *start, const u_char *data,
		   int len, uint16_t type)
{
	char buf[256];

	switch (type) {
	case 1: // A
		if (len != 4) {
			item_add_strf(rr_info, "Malformed A record");
			break;
		}
		inet_ntop(AF_INET, data, buf, sizeof(buf));
		item_add_strf(rr_info, "Address: %s", buf);
		break;
	case 5: // CNAME
		if (parse_label(data, start, len, buf) < 0) {
			item_add_strf(rr_info, "Malformed CNAME record");
			break;
		}
		item_add_strf(rr_info, "CNAME: %s", buf);
		break;
	case 15: // MX
		if (len < 2) {
			item_add_strf(rr_info, "Malformed MX record");
			break;
		}
		uint16_t preference = ntohs(*((uint16_t *)data));
		if (parse_label(data + 2, start, len - 2, buf) < 0) {
			item_add_strf(rr_info, "Malformed MX record");
			break;
		}
		item_add_strf(rr_info, "MX: %s (preference: %d)", buf,
			      preference);
		break;
	case 16: // TXT
		if (len < 1) {
			item_add_strf(rr_info, "Malformed TXT record");
			break;
		}
		uint8_t txt_len = *data;
		if (txt_len > len - 1) {
			item_add_strf(rr_info, "Malformed TXT record");
			break;
		}
		memcpy(buf, data + 1, txt_len);
		buf[txt_len] = '\0';
		item_add_strf(rr_info, "TXT: %s", buf);
		break;
	case 28: // AAAA
		if (len != 16) {
			item_add_strf(rr_info, "Malformed AAAA record");
			break;
		}
		inet_ntop(AF_INET6, data, buf, sizeof(buf));
		item_add_strf(rr_info, "Address: %s", buf);
		break;
	case 33: // SRV
		if (len < 6) {
			item_add_strf(rr_info, "Malformed SRV record");
			break;
		}
		uint16_t priority = ntohs(*((uint16_t *)data));
		uint16_t weight = ntohs(*((uint16_t *)(data + 2)));
		uint16_t port = ntohs(*((uint16_t *)(data + 4)));
		if (parse_label(data + 6, start, len - 6, buf) < 0) {
			item_add_strf(rr_info, "Malformed SRV record");
			break;
		}
		item_add_strf(rr_info, "SRV: %s:%d (priority: %d, weight: %d)",
			      buf, port, priority, weight);
		break;
	default:
		item_add_strf(rr_info, "Unknown record type");
		break;
	}
}

int parse_dns_record(const u_char **ptr_buffer, const u_char *start,
		     size_t *ptr_len, item *record)
{
	char rname[256];
	int label_len;

	const u_char *buffer = *ptr_buffer;
	size_t len = *ptr_len;

	if ((label_len = parse_label(buffer, start, len, rname)) < 0)
		return -1;

	buffer += label_len;
	len -= label_len;

	if (len < sizeof(struct dns_rr))
		return -1;

	struct dns_rr *rr = (struct dns_rr *)buffer;

	item *info = item_add_strf(record, "%s", rname);
	item_add_strf(info, "Name: %s", rname);
	item_add_strf(info, "Type: %d", ntohs(rr->type));
	item_add_strf(info, "Class: %d", ntohs(rr->class));
	item_add_strf(info, "TTL: %d", ntohl(rr->ttl));
	item_add_strf(info, "DLength: %d", ntohs(rr->rdlength));

	buffer += sizeof(struct dns_rr);
	len -= sizeof(struct dns_rr);

	parse_rr_data(info, start, buffer, ntohs(rr->rdlength),
		      ntohs(rr->type));

	*ptr_buffer = buffer;
	*ptr_len = len;
	return 0;
}

int dissector_dns(struct packet_info *pi, const u_char *buffer, size_t len)
{
	const u_char *start = buffer;
	struct dns_header *header = (struct dns_header *)buffer;
	item *info = item_add_strf(pi->root, "Domain Name System");

	if (len < sizeof(struct dns_header))
		goto malformed;

	item_add_strf(info, "ID: %d", ntohs(header->id));
	item_add_strf(info, "Flags: 0x%04x", ntohs(header->flags));
	item_add_strf(info, "QDcount: %d", ntohs(header->qdcount));
	item_add_strf(info, "ANcount: %d", ntohs(header->ancount));
	item_add_strf(info, "NScount: %d", ntohs(header->nscount));
	item_add_strf(info, "ARcount: %d", ntohs(header->arcount));

	buffer += sizeof(struct dns_header);
	len -= sizeof(struct dns_header);

	int i;

	item *record;

	if (ntohs(header->qdcount) > 0)
		record = item_add_strf(info, "Queries");
	for (i = 0; i < ntohs(header->qdcount); i++) {
		char qname[256];
		int label_len;

		if ((label_len = parse_label(buffer, start, len, qname)) < 0)
			goto malformed;

		if (len < sizeof(struct dns_question))
			goto malformed;

		struct dns_question *question = (struct dns_question *)buffer;

		item *info = item_add_strf(record, "%s", qname);
		item_add_strf(info, "Name: %s", qname);
		item_add_strf(info, "Type: %d", ntohs(question->type));
		item_add_strf(info, "Class: %d", ntohs(question->class));

		buffer += sizeof(struct dns_question);
		len -= sizeof(struct dns_question);
	}

	if (ntohs(header->ancount) > 0)
		record = item_add_strf(info, "Answers");
	for (int i = 0; i < ntohs(header->ancount); i++)
		if (parse_dns_record(&buffer, start, &len, record) < 0)
			goto malformed;

	if (ntohs(header->nscount) > 0)
		record = item_add_strf(info, "Authorities");
	for (int i = 0; i < ntohs(header->nscount); i++)
		if (parse_dns_record(&buffer, start, &len, record) < 0)
			goto malformed;

	if (ntohs(header->arcount) > 0)
		record = item_add_strf(info, "Additional");
	for (int i = 0; i < ntohs(header->arcount); i++)
		if (parse_dns_record(&buffer, start, &len, record) < 0)
			goto malformed;

	return 0;
malformed:
	item_set_strf(info, "Domain Name System [Malformed]");
	return -1;
}
