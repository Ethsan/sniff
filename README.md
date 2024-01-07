# Sniff is a simple network sniffer

This is a school project

# Protocol Supported

It currently support:

- ethernet
- Linux Precooked Socket
- IP
- UDP
- TCP
- ICMP
- ARP
- BOOTP/DHCP
- DNS
- HTTP
- FTP
- SMTP
- TELNET

# Build

To build simply run ```make```

# Makefile

Some header files need to be generated if there are deleted, simply run :
```
make src/utils/gen_tcp_port.fish
make src/utils/gen_udp_port.fish
```
NOTE: You shouldn't have to do it. It required ```fish```.

If you use clangd, you may want to generate the compile_commands.json, so simply run :

```
make compile_commands.json
```
NOTE: It required ```bear```

# Test

No test are currently implemented.
