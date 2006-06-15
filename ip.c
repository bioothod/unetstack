/*
 * 	ip.c
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

int packet_ip_send(struct nc_buff *ncb)
{
	struct iphdr *iph;

	iph = ncb_put(ncb, sizeof(struct iphdr));
	if (!iph)
		return -ENOMEM;

	iph->saddr = ncb->dst->src;
	iph->daddr = ncb->dst->dst;
	iph->check = 0;
	iph->tos = 0;
	iph->tot_len = htons(ncb->size);
	iph->ttl = 64;
	iph->id = 0;
	iph->frag_off = htons(0x4000);
	iph->version = 4;
	iph->ihl = 5;
	iph->protocol = ncb->dst->proto;

	iph->check = in_csum((__u16 *)iph, iph->ihl*4);
		
	if (ncb->dst->proto == IPPROTO_TCP) {
		struct tcphdr *th = (struct tcphdr *)(((__u8 *)iph) + iph->ihl*4);
		ulog("S %u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u : seq: %u, ack: %u, win: %u, doff: %u, "
			"s: %u, a: %u, p: %u, r: %u, f: %u: tlen: %u.\n",
			NIPQUAD(iph->saddr), ntohs(th->source),
			NIPQUAD(iph->daddr), ntohs(th->dest),
			ntohl(th->seq), ntohl(th->ack_seq), ntohs(th->window), th->doff,
			th->syn, th->ack, th->psh, th->rst, th->fin,
			ntohs(iph->tot_len));
	}
	return packet_eth_send(ncb);
}

int packet_ip_process(struct nc_buff *ncb)
{
	struct iphdr *iph;
	struct unetchannel unc;
	int err;

	ncb->nh.iph = iph = ncb_get(ncb, sizeof(struct iphdr));
	if (!iph)
		return -ENOMEM;
	
	ncb_get(ncb, iph->ihl * 4 - sizeof(struct iphdr));
	ncb_trim(ncb, ntohs(iph->tot_len) - iph->ihl * 4);

	unc.proto = iph->protocol;
	unc.src = iph->daddr;
	unc.dst = iph->saddr;
	unc.sport = ((__u16 *)(iph + 1))[1];
	unc.dport = ((__u16 *)(iph + 1))[0];

	err = netchannel_queue(ncb, &unc);
	return err;
}
