/*
 * 	udp.c
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
#include <errno.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>

#include "sys.h"

struct udp_protocol
{
	struct common_protocol	cproto;
	struct nc_buff_head	receive_queue;
};

struct pseudohdr
{
	__u32		saddr, daddr;
	__u8		empty;
	__u8		tp;
	__u32		len;
} __attribute__ ((packed));

static inline struct udp_protocol *udp_convert(struct common_protocol *proto)
{
	return (struct udp_protocol *)proto;
}

static int udp_connect(struct common_protocol *proto,
		struct netchannel *nc __attribute__ ((unused)))
{
	struct udp_protocol *up = udp_convert(proto);
	ncb_queue_init(&up->receive_queue);
	return 0;
}

static int udp_build_header(struct udp_protocol *up, struct nc_buff *ncb)
{
	struct udphdr *uh;
	struct pseudohdr *p;

	uh = ncb->h.uh = ncb_push(ncb, sizeof(struct udphdr));
	if (!uh)
		return -ENOMEM;
	
	uh->source = ncb->nc->unc.sport;
	uh->dest = ncb->nc->unc.dport;
	uh->len = htons(ncb->size);
	uh->check = 0;
	
	p = (struct pseudohdr *)(((__u8 *)uh) - sizeof(struct pseudohdr));
	memset(p, 0, sizeof(*p));

	p->saddr = ncb->nc->unc.src;
	p->daddr = ncb->nc->unc.dst;
	p->tp = IPPROTO_UDP;
	p->len = htonl(ncb->size);

	uh->check = in_csum((__u16 *)p, sizeof(struct pseudohdr) + ncb->size);
	return ip_build_header(ncb);
}

static int udp_process_in(struct common_protocol *proto, struct nc_buff *ncb)
{
	struct udp_protocol *up = udp_convert(proto);

	if (!ncb)
		return 0;
	
	ncb->h.raw = ncb_pull(ncb, sizeof(struct udphdr));
	if (!ncb->h.raw)
		return -EINVAL;

	ncb_queue_tail(&up->receive_queue, ncb);
	return ncb->size;
}

static int udp_process_out(struct common_protocol *proto, struct nc_buff *ncb)
{
	int err;
	struct udp_protocol *up = udp_convert(proto);

	err = udp_build_header(up, ncb);
	if (err)
		return err;

	return transmit_data(ncb);
}

static int udp_read_data(struct common_protocol *proto, __u8 *buf, unsigned int size)
{
	struct udp_protocol *up = udp_convert(proto);
	struct nc_buff *ncb = ncb_peek(&up->receive_queue);
	unsigned int sz;
	
	if (!ncb)
		return -EAGAIN;

	ncb_unlink(ncb, &up->receive_queue);
	sz = min_t(unsigned int, size, ncb->size);
	memcpy(buf, ncb->head, sz);
	ncb_put(ncb);
	return sz;
}

static int udp_destroy(struct common_protocol *proto __attribute__ ((unused)),
		struct netchannel *nc __attribute__ ((unused)))
{
	return 0;
}

struct common_protocol udp_protocol = {
	.size		= sizeof(struct udp_protocol),
	.connect	= &udp_connect,
	.process_in	= &udp_process_in,
	.process_out	= &udp_process_out,
	.read_data	= &udp_read_data,
	.destroy	= &udp_destroy,
};
