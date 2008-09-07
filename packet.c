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

#include <linux/if_ether.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "sys.h"
#include "stat.h"

static int need_exit;
static int alarm_timeout = 1;

extern unsigned char packet_edst[];
extern int packet_index;

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
	if (ncb->nc->ctl.saddr.proto == IPPROTO_TCP) {
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

static int netchannel_addr_init(struct netchannel_addr *a, char *addr, unsigned short port, int proto)
{
	struct addrinfo *h, hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_protocol = proto;

	if (getaddrinfo(addr, "", &hints, &h)) {
		ulog_err("%s: Failed to get address of '%s'.\n", __func__, addr);
		return -1;
	}

	if (h->ai_family == AF_INET) {
		struct sockaddr_in *sa = (struct sockaddr_in *)h->ai_addr;

		a->size = sizeof(sa->sin_addr);
		memcpy(&a->addr, &sa->sin_addr, a->size);
	} else {
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)h->ai_addr;

		a->size = sizeof(sa6->sin6_addr);
		memcpy(&a->addr, &sa6->sin6_addr, a->size);
	}

	a->proto = proto;
	a->port = htons(port);

	freeaddrinfo(h);
	return 0;
}

static int packet_parse_addr(char *str, unsigned char addr[])
{
	int i;
	char *p = str;

	/*
	 * 00:11:22:33:44:55
	 */
	if (strlen(str) != 2*ETH_ALEN + ETH_ALEN-1) {
		ulog("Wrong ethernet address string '%s', it has to be in the wollowing form: 00:11:22:33:44:55.\n",
				str);
		return -EINVAL;
	}

	for (i=0; i<ETH_ALEN; ++i) {
		p = str+2;
		*p = 0;

		addr[i] = strtoul(str, NULL, 16);

		str = p+1;
	}

	return 0;
}

static void usage(const char *p)
{
	ulog_info("Usage: %s -s saddr -S sport -d daddr -D dport -p proto -l <listen> -L packet_limit -b size -e eth_dst_addr -i eth_out_index -h\n", p);
}

int main(int argc, char *argv[])
{
	int err, ch, sent, recv;
	struct netchannel *nc;
	char *src, *dst;
	__u16 sport, dport;
	__u8 proto;
	struct netchannel_control ctl;
	char str[4096];
	unsigned int state, size, limit;

	srand(time(NULL));

	src = dst = NULL;
	sport = dport = 0;
	proto = IPPROTO_TCP;
	state = NETCHANNEL_ATCP_CONNECT;
	size = sizeof(str);
	limit = 1024;

	while ((ch = getopt(argc, argv, "e:i:s:d:S:D:hp:lL:b:")) != -1) {
		switch (ch) {
			case 'i':
				packet_index = atoi(optarg);
				break;
			case 'e':
				err = packet_parse_addr(optarg, packet_edst);
				if (err)
					return err;
				break;
			case 'b':
				size = atoi(optarg);
				if (size > sizeof(str))
					size = sizeof(str);
				break;
			case 'l':
				state = NETCHANNEL_ATCP_LISTEN;
				break;
			case 'L':
				limit = atoi(optarg);
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
				dst = optarg;
				break;
			case 's':
				src = optarg;
				break;
			default:
				usage(argv[0]);
				return 0;
		}
	}

	if (!src || !dst || !sport || !dport) {
		usage(argv[0]);
		return -1;
	}

	err = netchannel_addr_init(&ctl.saddr, src, sport, proto);
	if (err)
		return err;
	
	err = netchannel_addr_init(&ctl.daddr, dst, dport, proto);
	if (err)
		return err;

	ctl.packet_limit = limit;

	nc = netchannel_create(&ctl, state);
	if (!nc)
		return -EINVAL;

	signal(SIGTERM, term_signal);
	signal(SIGINT, term_signal);
	signal(SIGALRM, alarm_signal);
	init_stat();
	alarm(alarm_timeout);

	sent = recv = 0;

	printf("size: %u.\n", size);

	while (!need_exit) {
		err = netchannel_send(nc, str, size);
		ulog("%s: recv: err: %d.\n", __func__, err);
		if (err > 0) {
			stat_written += err;
			stat_written_msg++;
			last_fd = nc->hit;
		} else if (err < 0) {
			if (err != -EAGAIN)
				need_exit = 1;
		}
	}

	netchannel_remove(nc);

	return err;
}
