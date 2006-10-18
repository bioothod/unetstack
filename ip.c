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

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "sys.h"

int ip_build_header(struct nc_buff *ncb)
{
	struct iphdr *iph;

	ncb->nh.iph = iph = ncb_push(ncb, sizeof(struct iphdr));
	if (!iph)
		return -ENOMEM;

	iph->saddr = ncb->dst->src;
	iph->daddr = ncb->dst->dst;
	iph->check = 0;
	iph->tos = 0x10;
	iph->tot_len = htons(ncb->len);
	iph->ttl = 64;
	iph->id = rand();
	iph->frag_off = htons(0x4000);
	iph->version = 4;
	iph->ihl = 5;
	iph->protocol = ncb->dst->proto;

	iph->check = in_csum((__u16 *)iph, iph->ihl*4);
	return 0;
}

int ip_send_data(struct nc_buff *ncb)
{
	int err;

	err = ip_build_header(ncb);
	if (err < 0)
		return err;
	return transmit_data(ncb);
}

int packet_ip_process(struct nc_buff *ncb)
{
	struct iphdr *iph;

	ncb->nh.iph = iph = ncb_pull(ncb, sizeof(struct iphdr));
	if (!iph)
		return -ENOMEM;
	
	ncb_pull(ncb, iph->ihl * 4 - sizeof(struct iphdr));
	ncb_trim(ncb, ntohs(iph->tot_len) - iph->ihl * 4);

	ncb_queue_tail(&ncb->nc->recv_queue, ncb);
	ncb->nc->hit++;

	ulog("%s: queued packet: %u.%u.%u.%u -> %u.%u.%u.%u, hit: %llu.\n",
			__func__, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ncb->nc->hit);

	return 0;
}
