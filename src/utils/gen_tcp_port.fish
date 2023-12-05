#!/bin/fish

echo	"static const char *get_tcp_port(unsigned short port)"
echo	"{"
echo	"	switch (port) {"

curl -s https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv | \
	grep ",[0-9]\+,tcp" | \
	tr -d \" | \
	awk -F, '!(NF && seen[$2]++) {print "\tcase "$2":\n\t\treturn \""$4"\";"}'

echo	"	default:"
echo	"		if (port >= 49152 && port <= 65535)"
echo	"			return \"Dynamic\";"
echo	"		return \"Unknown\";"
echo	"	};"
echo	"}"
