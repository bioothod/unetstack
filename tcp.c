/*
 * 	tcp.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <netpacket/packet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "sys.h"

static int tcp_connect(struct protocol *proto, struct netchannel *nc)
{
	int err = -ENOMEM;
	struct tcphdr *th;
	struct nc_buff *ncb;
	unsigned int size = sizeof(struct tcphdr) + sizeof(struct iphdr) + sizeof(struct ether_header);
	struct nc_route dst;

	ncb = ncb_alloc(size);
	if (!ncb)
		goto err_out_free;

	err = -EINVAL;
	if (ncb_get(ncb, size))
		goto err_out_free;

	th = ncb_put(ncb, sizeof(struct tcphdr));
	if (!th)
		goto err_out_free;

	th->source = nc->unc.sport;
	th->dest = nc->unc.dport;
	th->seq = 100;
	th->ack = 0;
	
	th->syn = 1;
	th->window = 1024;
	th->check = 0;
	
	return 0;
		
err_out_free:
	ncb_free(ncb);
	return err;
}

static int tcp_process_in(struct protocol *proto, struct netchannel *nc, struct nc_buff *ncb, unsigned int size)
{
	struct tcphdr *th;

	th = ncb_get(ncb, sizeof(struct tcphdr));

	ulog("sport: %u, dport: %u, seq: %u, ack: %u, win: %u, flags: syn: %u, ack: %u, psh: %u, rst: %u, fin: %u, req_size: %u.\n",
			ntohs(th->source), ntohs(th->dest),
			ntohl(th->seq), ntohl(th->ack_seq), ntohs(th->window),
			th->syn, th->ack, th->psh, th->rst, th->fin,
			size);
	return 0;
}

static int tcp_process_out(struct protocol *proto, struct netchannel *nc, struct nc_buff *ncb, unsigned int size)
{
	return 0;
}

static int tcp_destroy(struct protocol *proto, struct netchannel *nc)
{
	return 0;
}

struct protocol tcp_protocol = {
	.state		= 0,
	.connect	= &tcp_connect,
	.process_in	= &tcp_process_in,
	.process_out	= &tcp_process_out,
	.destroy	= &tcp_destroy,
};
