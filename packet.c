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
#include <sys/socket.h>
#include <sys/poll.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "sys.h"

static int need_exit;
static int alarm_timeout = 5;

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

static void term_signal(int signo)
{
	need_exit = signo;
}

static int packet_create_socket(void)
{
	int s;
	struct sockaddr_ll ll;

	s = socket(PF_PACKET, SOCK_DGRAM, 0);
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

static int packet_process_tcp(struct iphdr *iph)
{
	struct tcphdr *th;

	th = (struct tcphdr *)(((__u8 *)iph) + iph->ihl*4);

	ulog("%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u : seq: %u, ack: %u, win: %u, flags: syn: %u, ack: %u, psh: %u, rst: %u, fin: %u.\n",
			NIPQUAD(iph->saddr), ntohs(th->source),
			NIPQUAD(iph->daddr), ntohs(th->dest),
			ntohl(th->seq), ntohl(th->ack_seq), ntohs(th->window),
			th->syn, th->ack, th->psh, th->rst, th->fin);

	return 0;
}

static int packet_process(int s)
{
	unsigned char buf[4096];
	int err;
	struct sockaddr_in from;
	socklen_t from_len = sizeof(struct sockaddr_in);
	struct iphdr *iph;
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

	iph = (struct iphdr *)&buf[0];
#if 0
	ulog("%u.%u.%u.%u -> %u.%u.%u.%u, size: %d.\n",
			NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), err);
#endif
	switch (iph->protocol) {
		case IPPROTO_TCP:
			err = packet_process_tcp(iph);
			break;
		default:
			err = -ENODEV;
			break;
	}


	return err;
}

int main()
{
	int s;

	s = packet_create_socket();
	if (s == -1)
		return -1;

	signal(SIGTERM, term_signal);
	signal(SIGINT, term_signal);

	while (!need_exit) {
		packet_process(s);
	}

	return 0;
}
