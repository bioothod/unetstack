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
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>
#include <time.h>

#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "sys.h"
#include "stat.h"

static int need_exit;
static int packet_socket;
static int alarm_timeout = 1;

/* Maximum number of not related to netchannel packets to read from packet socket until return */
static int packet_max_read_num = 50;

static void term_signal(int signo)
{
	need_exit = signo;
}

static void alarm_signal(int signo __attribute__ ((unused)))
{
	print_stat();
	alarm(alarm_timeout);
}

static int packet_send(struct nc_buff *ncb)
{
	struct pollfd pfd;
	int err;
	struct sockaddr_ll ll;

	pfd.fd = packet_socket;
	pfd.events = POLLOUT;
	pfd.revents = 0;

	if (poll(&pfd, 1, 1000) <= 0)
		return -1;

	if (!(pfd.revents & POLLOUT))
		return -1;

	ll.sll_family = PF_PACKET;
	ll.sll_protocol = htons(ETH_P_IP);
	ll.sll_hatype = PACKET_OTHERHOST;
	ll.sll_halen = ETH_ALEN;
	ll.sll_ifindex = 2;
	memcpy(ll.sll_addr, ncb->dst->edst, ll.sll_halen);

	err = sendto(pfd.fd, ncb->head, ncb->len, 0, (struct sockaddr *)&ll, sizeof(struct sockaddr_ll));
	if (err < 0) {
		ulog_err("sendto");
		return err;
	}

	return 0;
}

int transmit_data(struct nc_buff *ncb)
{
	int err;
#if defined UDEBUG
	if (ncb->dst->proto == IPPROTO_TCP) {
		struct iphdr *iph = ncb->nh.iph;
		struct tcphdr *th = ncb->h.th;
		ulog("S %u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u : seq: %u, ack: %u, win: %u, doff: %u, "
			"s: %u, a: %u, p: %u, r: %u, f: %u: tlen: %u.\n",
			NIPQUAD(iph->saddr), ntohs(th->source),
			NIPQUAD(iph->daddr), ntohs(th->dest),
			ntohl(th->seq), ntohl(th->ack_seq), ntohs(th->window), th->doff,
			th->syn, th->ack, th->psh, th->rst, th->fin,
			ntohs(iph->tot_len));
	}
#endif
	err = packet_send(ncb);
	if (err)
		return err;

	ncb_put(ncb);
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

int packet_process(unsigned int timeout)
{
	unsigned char buf[4096];
	int err, i;
	struct sockaddr_in from;
	socklen_t from_len = sizeof(struct sockaddr_in);
	struct pollfd pfd;

	for (i=0; i<packet_max_read_num; ++i) {
		pfd.fd = packet_socket;
		pfd.events = POLLIN;
		pfd.revents = 0;

		err = poll(&pfd, 1, timeout);

		if (pfd.revents & POLLIN) {
			err = recvfrom(packet_socket, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
			if (err < 0) {
				ulog_err("recvfrom");
				return err;
			}

			err = packet_eth_process(buf, err);
			if (!err)
				break;
		}
	}

	return err;
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
	ulog_info("Usage: %s -s saddr -d daddr -S sport -D dport -p proto -h\n", p);
}

int main(int argc, char *argv[])
{
	int err, ch, send_num;
	struct unetchannel unc;
	struct netchannel *nc;
	char *saddr, *daddr;
	__u32 src, dst;
	__u16 sport, dport;
	__u8 proto;
	unsigned char buf[4096];
	//__u8 edst[] = {0x00, 0x0E, 0x0C, 0x81, 0x20, 0xFF}; /* e1000 old*/
	//__u8 edst[] = {0x00, 0x90, 0x27, 0xAF, 0x83, 0x81}; /* dea */
	//__u8 edst[] = {0x00, 0x10, 0x22, 0xFD, 0xC4, 0xD6}; /* 3com*/
	//__u8 edst[] = {0x00, 0x0C, 0x6E, 0xAD, 0xBB, 0x8B}; /* kano */
	//__u8 edst[] = {0x00, 0xE0, 0x18, 0xF5, 0x9D, 0xE6}; /* linoleum2 */
	__u8 edst[] = {0x00, 0x08, 0xC7, 0x2A, 0xD2, 0x63}; /* e1000 new */
	//__u8 edst[] = {0x00, 0x00, 0x21, 0x01, 0x95, 0xD1}; /* home lan */
	__u8 esrc[] = {0x00, 0x11, 0x09, 0x61, 0xEB, 0x0E};
	struct nc_route rt;
	char str[128];
	
	rt.src = num2ip(192,168,4,78);
	rt.dst = num2ip(192,168,0,48);
	memcpy(rt.edst, edst, ETH_ALEN);
	memcpy(rt.esrc, esrc, ETH_ALEN);
	
	srand(time(NULL));

	saddr = "192.168.0.48";
	daddr = "192.168.4.78";
	sport = rand();
	dport = 1025;
	proto = IPPROTO_TCP;
	send_num = 1;

	while ((ch = getopt(argc, argv, "n:s:d:S:D:hp:")) != -1) {
		switch (ch) {
			case 'n':
				send_num = atoi(optarg);
				break;
			case 'p':
				proto = atoi(optarg);
				break;
			case 'D':
				dport = atoi(optarg);
				break;
			case 'S':
				sport = atoi(optarg);
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
	
	err = route_init();
	if (err)
		return err;
	
	rt.header_size = MAX_HEADER_SIZE;
	rt.src = src;
	rt.dst = dst;
	rt.proto = proto;
	memcpy(rt.edst, edst, ETH_ALEN);
	memcpy(rt.esrc, esrc, ETH_ALEN);

	err = route_add(&rt);
	if (err)
		return err;

	packet_socket = packet_create_socket();
	if (packet_socket == -1)
		return -1;

	signal(SIGTERM, term_signal);
	signal(SIGINT, term_signal);
	signal(SIGALRM, alarm_signal);
	init_stat();
	alarm(alarm_timeout);

	unc.laddr = src;
	unc.faddr = dst;
	unc.lport = htons(sport);
	unc.fport = htons(dport);
	unc.proto = proto;
	
	nc = netchannel_create(&unc);
	if (!nc)
		return -1;
	
	ulog("Connected.\n");
	while (!need_exit) {
		static int sent, recv;
		int i;
#if 1
		packet_process(100);
		err = netchannel_recv(nc, buf, sizeof(buf));
		if (err > 0) {
			recv++;
			write(2, buf, err);
		}
#endif
		for (i=0; i<send_num; ++i)
		{
			memset(str, 0xab, sizeof(str));
			snprintf(str, sizeof(str), "Counter: sent: %u, recv: %u.\n", sent, recv);
			err = netchannel_send(nc, str, sizeof(str));
			ulog("%s: send: err: %d.\n", __func__, err);
			if (err > 0) {
				stat_written += err;
				stat_written_msg++;
				last_fd = nc->hit;
			} else {
				if (err != -EAGAIN)
					need_exit = 1;
				break;
			}

		}
#if 0
		{
			//__u8 str[] = "GET http://lcamtuf.coredump.cx/p0f-help/ HTTP/1.0\n\n";
			__u8 str[] = "GET / HTTP/1.0\n\n";

			if ((recv == 1) &&!sent && (netchannel_send(nc, str, sizeof(str)) >= 0))
				sent = 1;
		}
#endif
	}

	return 0;
}
