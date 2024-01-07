#include <netinet/ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <string.h>
#include <time.h>

#include "dissector/dissector.h"
#include "capture.h"
#include "item.h"

#define SNAPLEN 65535
#define BUF_TIMEOUT 1000
#define SET_PROMISC 1

char errbuf[PCAP_ERRBUF_SIZE];

struct context {
	int datalink;
	int verbose;
	int count;
};

void print_line(struct packet_info info, FILE *stream)
{
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];

	switch (info.src.type) {
	case ADDRESS_TYPE_IP:
		inet_ntop(AF_INET, info.src.ip, src, sizeof(src));
		break;
	case ADDRESS_TYPE_IP6:
		inet_ntop(AF_INET6, info.src.ip, src, sizeof(src));
		break;
	case ADDRESS_TYPE_MAC:
		strcpy(src, ether_ntoa((struct ether_addr *)info.src.mac));
		break;
	default:
		strcpy(src, "Unknown");
	}
	switch (info.dst.type) {
	case ADDRESS_TYPE_IP:
		inet_ntop(AF_INET, info.dst.ip, dst, sizeof(dst));
		break;
	case ADDRESS_TYPE_IP6:
		inet_ntop(AF_INET6, info.dst.ip, dst, sizeof(dst));
		break;
	case ADDRESS_TYPE_MAC:
		strcpy(dst, ether_ntoa((struct ether_addr *)info.dst.mac));
		break;
	default:
		strcpy(dst, "Unknown");
	}

	item *proto = item_get_last_child(info.root);
	fprintf(stream, "%-7i %-7li %-15s -> %-15s %-15s\n", info.id,
		info.header.ts.tv_sec, src, dst, item_get_str(proto));
}

void capture_handler(u_char *user, const struct pcap_pkthdr *h,
		     const u_char *bytes)
{
	char timebuf[128];
	item *item;

	struct context *c = (typeof(c))user;
	struct packet_info info = { 0 };

	info.header = *h;
	info.id = c->count++;

	if (h->len < h->caplen)
		warnx("Packet %i: truncated packet", info.id);

	info.root = item_new_strf("Frame %i", info.id);

	item = item_add_strf(info.root,
			     "Packet %i: %i bytes on wire, %i bytes captured",
			     info.id, info.header.len, info.header.caplen);

	strftime(timebuf, sizeof(timebuf), "Arrival time: %Y-%m-%d %H:%M:%S",
		 localtime(&info.header.ts.tv_sec));

	item_add_str(item, timebuf);
	item_add_strf(item, "Frame number: %i", info.id);
	item_add_strf(item, "Frame length: %i", info.header.len);
	item_add_strf(item, "Capture length: %i", info.header.caplen);

	switch (c->datalink) {
	case DLT_EN10MB:
		dissector_ethernet(&info, bytes, h->caplen);
		break;
	case DLT_LINUX_SLL:
		dissector_linux_sll(&info, bytes, h->caplen);
		break;
	default:
		warnx("Packet %i: unsupported data link type (%d)", info.id,
		      c->datalink);
	}

	if (c->verbose == 1) {
		print_line(info, stdout);
	} else if (c->verbose == 2) {
		item_print(info.root, stdout, 1);
	} else if (c->verbose == 3) {
		item_print(info.root, stdout, 0);
	}

	fprintf(stdout, "\n");

	item_free_all(info.root);
}

bpf_u_int32 get_netmask(const char *interface)
{
	bpf_u_int32 netmask = PCAP_NETMASK_UNKNOWN;

	if (interface == NULL) {
		warnx("no interface specified, netmask will be set to PCAP_NETMASK_UNKNOWN");
		return netmask;
	}

	if (pcap_lookupnet(interface, NULL, &netmask, errbuf) != 0) {
		warnx("pcap_lookupnet: %s, netmask will be set to PCAP_NETMASK_UNKNOWN",
		      errbuf);
	}
	return netmask;
}

int set_filter(pcap_t *pcap, const char *filter, bpf_u_int32 netmask)
{
	struct bpf_program fp;

	if (pcap_compile(pcap, &fp, filter, 1, netmask) != 0) {
		warnx("pcap_compile: %s", pcap_geterr(pcap));
		return -1;
	}
	if (pcap_setfilter(pcap, &fp) != 0) {
		warnx("pcap_setfilter: %s", pcap_geterr(pcap));
		return -1;
	}
	return 0;
}

pcap_t *get_pcap_t(const char *interface, const char *file)
{
	pcap_t *pcap = NULL;

	if (interface != NULL) {
		errbuf[0] = '\0';
		pcap = pcap_open_live(interface, SNAPLEN, SET_PROMISC,
				      BUF_TIMEOUT, errbuf);

		if (pcap == NULL || errbuf[0] != '\0')
			warnx("pcap_open_live: %s",
			      errbuf); // error or warning

	} else if (file != NULL) {
		pcap = pcap_open_offline(file, errbuf);

		if (pcap == NULL)
			warnx("pcap_open_offline: %s", errbuf);
	} else {
		warnx("no interface or file specified");
	}

	return pcap;
}

void capture(struct options *options)
{
	pcap_t *pcap;
	int ret;

	struct context context = { .verbose = options->verbose,
				   .datalink = -1,
				   .count = 0 };

	if (pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf) != 0)
		errx(EXIT_FAILURE, "pcap_init: %s", errbuf);

	pcap = get_pcap_t(options->interface, options->file);
	if (pcap == NULL)
		errx(EXIT_FAILURE, "get_pcap_t");

	context.datalink = pcap_datalink(pcap);
	switch (context.datalink) {
	case DLT_EN10MB:
	case DLT_LINUX_SLL:
		break; // Supported
	case PCAP_ERROR_NOT_ACTIVATED:
		errx(EXIT_FAILURE, "pcap_datalink: %s", pcap_geterr(pcap));
	default:
		errx(EXIT_FAILURE, "unsupported data link type (%d)",
		     context.datalink);
	}

	if (options->filter != NULL) {
		bpf_u_int32 netmask = get_netmask(options->interface);

		if (set_filter(pcap, options->filter, netmask) < 0)
			errx(EXIT_FAILURE, "set_filter failed");
	}

	if (context.verbose == 1)
		fprintf(stdout,
			"No.     Time           Source                Destination           Protocol\n");

	ret = pcap_loop(pcap, -1, capture_handler, (u_char *)&context);
	if (ret != 0)
		errx(EXIT_FAILURE, "pcap_loop: %s", pcap_geterr(pcap));
}
