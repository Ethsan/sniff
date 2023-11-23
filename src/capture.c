#include <stdlib.h>
#include <pcap.h>
#include <err.h>

#include "capture.h"
#include "packet.h"
#include "item_list.h"

#define SNAPLEN 65535
#define BUF_TIMEOUT 1000
#define SET_PROMISC 1

char errbuf[PCAP_ERRBUF_SIZE];

struct context {
	const char *interface;
	int datalink;
	int verbose;

	struct timeval start;
	int count;
};

void capture_handler(u_char *user, const struct pcap_pkthdr *h,
		     const u_char *bytes)
{
	struct context *c = (typeof(c))user;
	(void)c;
	(void)h;
	(void)bytes;
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
			warnx("pcap_open_live: %s", errbuf); // error or warning

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
				   .count = 0,
				   .start = { 0 },
				   .interface = options->interface };

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

	ret = pcap_loop(pcap, -1, capture_handler, (u_char *)&context);
	if (ret != 0)
		errx(EXIT_FAILURE, "pcap_loop: %s", pcap_geterr(pcap));
}
