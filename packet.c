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

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "sys.h"
#include "stat.h"

static int need_exit;
static int alarm_timeout = 1;

static void term_signal(int signo)
{
	need_exit = signo;
}

static void alarm_signal(int signo __attribute__ ((unused)))
{
	print_stat();
	alarm(alarm_timeout);
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
	err = netchannel_send_raw(ncb);
	if (err)
		return err;

	ncb_put(ncb);
	return 0;
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
	ulog_info("Usage: %s -s saddr -d daddr -S sport -D dport -p proto -t timeout -l -o order -h\n", p);
}

int main(int argc, char *argv[])
{
	int err, ch, send_num, sent, recv, i;
	struct unetchannel unc;
	struct netchannel *nc;
	char *saddr, *daddr;
	__u32 src, dst;
	__u16 sport, dport;
	__u8 proto;
	struct nc_route rt;
	char str[128];
	unsigned int timeout, state, order;

	srand(time(NULL));

	saddr = "192.168.4.78";
	daddr = "192.168.0.48";
	sport = rand();
	dport = 1025;
	proto = IPPROTO_TCP;
	send_num = 1;
	timeout = 0;
	state = NETCHANNEL_ATCP_CONNECT;
	order = 20;

	while ((ch = getopt(argc, argv, "n:s:d:S:D:hp:t:lo:")) != -1) {
		switch (ch) {
			case 'o':
				order = atoi(optarg);
				break;
			case 'l':
				state = NETCHANNEL_ATCP_LISTEN;
				break;
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
			case 't':
				timeout = atoi(optarg);
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

	err = route_init();
	if (err)
		return err;

	rt.header_size = MAX_HEADER_SIZE;
	rt.src = src;
	rt.dst = dst;
	rt.proto = proto;

	err = route_add(&rt);
	if (err)
		return err;

	netchannel_setup_unc(&unc, src, sport, dst, dport, proto, state, timeout, order);
	nc = netchannel_create(&unc);
	if (!nc)
		return -EINVAL;

	signal(SIGTERM, term_signal);
	signal(SIGINT, term_signal);
	signal(SIGALRM, alarm_signal);
	init_stat();
	alarm(alarm_timeout);

	sent = recv = 0;

	while (!need_exit) {
		for (i=0; i<send_num; ++i) {
			err = netchannel_recv(nc, str, sizeof(str));
			ulog("%s: recv: err: %d.\n", __func__, err);
			if (err > 0) {
				stat_written += err;
				stat_written_msg++;
				last_fd = nc->hit;
			} else if (err < 0) {
				if (err != -EAGAIN)
					need_exit = 1;
				break;
			}

		}
	}

	netchannel_remove(nc);

	return 0;
}
