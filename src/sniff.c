#include <argp.h>
#include <stdnoreturn.h>
#include <stdlib.h>

#include "capture.h"

noreturn void usage(char *name, int status)
{
	fprintf(stderr, "Usage: %s <-i <interface>|-f <file>> [options]\n",
		name);
	fputs("-i <interface> interface for the live analysis\n"
	      "-o <file>      read packets from file\n\n"
	      "-h             print this message\n"
	      "-f <filter>    filter BPF\n"
	      "-v <1..3>      verbosity level (1=short, 2=concise, 3=full)\n",
	      stderr);
	exit(status);
}

int main(int argc, char *argv[])
{
	int c;

	struct options options = { 0 };

	if (argc < 2)
		usage(argv[0], EXIT_FAILURE);

	while ((c = getopt(argc, argv, "f:i:o:v:h")) != -1)
		switch (c) {
		case 'f':
			options.file = optarg;
			break;
		case 'i':
			options.interface = optarg;
			break;
		case 'o':
			options.file = optarg;
			break;
		case 'v':
			options.verbose = atoi(optarg);
			break;
		case 'h':
			usage(argv[0], EXIT_SUCCESS);
		default:
			usage(argv[0], EXIT_FAILURE);
		}

	if (options.interface == NULL && options.file == NULL)
		usage(argv[0], EXIT_FAILURE);
	if (options.interface != NULL && options.file != NULL)
		usage(argv[0], EXIT_FAILURE);

	if (options.verbose < 1 || options.verbose > 3)
		options.verbose = 1;

	capture(&options);

	return EXIT_SUCCESS;
}
