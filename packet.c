/*
 * 	packet.c
 * 
 * 2006 Copyright (c) Evgeniy Polyakov <johnpol@2ka.mipt.ru>
 * All rights reserved.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "sys.h"

static int need_exit;
static int packet_socket;
//static int alarm_timeout = 5;

static void term_signal(int signo)
{
	need_exit = signo;
}

int packet_send(struct nc_buff *ncb)
{
	struct pollfd pfd;
	int err;

	pfd.fd = packet_socket;
	pfd.events = POLLOUT;
	pfd.revents = 0;

	if (poll(&pfd, 1, 1000) <= 0)
		return -1;

	if (!(pfd.revents & POLLOUT))
		return -1;

	err = sendto(pfd.fd, ncb->head, ncb->size, 0, NULL, 0);
	if (err < 0) {
		ulog_err("sendto");
		return err;
	}

	return 0;
}

static int packet_create_socket(void)
{
	int s;
	struct sockaddr_ll ll;

	s = socket(PF_PACKET, SOCK_RAW, 0);
	if (s == -1) {
		ulog_err("socket");
		return -1;
	}

	memset(&ll, 0, sizeof(struct sockaddr_ll));
	
	ll.sll_family = AF_PACKET;
	ll.sll_protocol = htons(ETH_P_ALL);
	ll.sll_pkttype = PACKET_OUTGOING;

	if (bind(s, (struct sockaddr *)&ll, sizeof(struct sockaddr_ll))) {
		ulog_err("bind");
		close(s);
		return -1;
	}

	return s;
}

void packet_dump(__u8 *data, unsigned int size)
{
	unsigned int i;

	ulog("dump: size: %u: ", size);
	for (i=0; i<min_t(unsigned int, size, 128); ++i)
		uloga("%02x ", data[i]);
	uloga("\n");
}

static int packet_process(int s)
{
	unsigned char buf[4096];
	int err;
	struct sockaddr_in from;
	socklen_t from_len = sizeof(struct sockaddr_in);
	struct pollfd pfd;

	pfd.fd = s;
	pfd.events = POLLIN;
	pfd.revents = 0;

	if (poll(&pfd, 1, 1000) <= 0)
		return -1;

	if (!(pfd.revents & POLLIN))
		return -1;

	err = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
	if (err < 0) {
		ulog_err("recvfrom");
		return err;
	}

	return packet_eth_process(buf, err);
}

static unsigned int packet_convert_addr(char *addr_str, unsigned int *addr)
{
	struct hostent *h;

	h = gethostbyname(addr_str);
	if (!h) {
		ulog_err("%s: Failed to get address of %s", __func__, addr_str);
		return -1;
	}
	
	memcpy(addr, h->h_addr_list[0], 4);
	return 0;
}

static void usage(const char *p)
{
	ulog("Usage: %s -s saddr -d daddr -S sport -D dport -p proto -h\n", p);
}

int main(int argc, char *argv[])
{
	int err, ch;
	struct unetchannel unc;
	struct netchannel *nc;
	char *saddr, *daddr;
	__u32 src, dst;
	__u16 sport, dport;
	__u8 proto;
	unsigned char buf[4096];

	saddr = "192.168.0.48";
	daddr = "192.168.4.78";
	sport = htons(1234);
	dport = htons(22);
	proto = IPPROTO_TCP;

	while ((ch = getopt(argc, argv, "s:d:S:D:hp:")) != -1) {
		switch (ch) {
			case 'p':
				proto = atoi(optarg);
				break;
			case 'D':
				dport = htons(atoi(optarg));
				break;
			case 'S':
				sport = htons(atoi(optarg));
				break;
			case 'd':
				daddr = optarg;
				break;
			case 's':
				saddr = optarg;
				break;
			default:
				usage(argv[0]);
				return 0;
		}
	}

	if (packet_convert_addr(saddr, &src) || packet_convert_addr(daddr, &dst)) {
		usage(argv[0]);
		return -1;
	}

	err = netchannel_init();
	if (err)
		return err;

	packet_socket = packet_create_socket();
	if (packet_socket == -1)
		return -1;

	signal(SIGTERM, term_signal);
	signal(SIGINT, term_signal);

	unc.src = src;
	unc.dst = dst;
	unc.sport = sport;
	unc.dport = dport;
	unc.proto = proto;
	
	nc = netchannel_create(&unc);
	if (!nc)
		return -1;

	err = netchannel_connect(nc);
	if (err)
		return -1;

	while (!need_exit) {
		err = packet_process(packet_socket);
		if (!err)
			netchannel_recv(nc, buf, sizeof(buf));
	}

	return 0;
}
