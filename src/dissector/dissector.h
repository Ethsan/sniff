#pragma once

#include "packet.h"

int dissector_generic(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_ethernet(struct packet_info *pi, const u_char *buffer,
		       size_t len);

int dissector_linux_sll(struct packet_info *pi, const u_char *buffer,
			size_t len);

int dissector_ipv4(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_ipv6(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_arp(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_tcp(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_udp(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_icmp(struct packet_info *pi, const u_char *buffer, size_t len);

int dissecotr_icmp6(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_dhcp(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_dns(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_smtp(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_pop(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_imap(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_http(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_ftp(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_https(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_ssh(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_telnet(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_sctp(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_ldap(struct packet_info *pi, const u_char *buffer, size_t len);

int dissector_bootp(struct packet_info *pi, const u_char *buffer, size_t len);
