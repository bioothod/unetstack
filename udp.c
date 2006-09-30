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

static int udp_connect(struct netchannel *nc)
{
	struct udp_protocol *up = udp_convert(nc->proto);
	ncb_queue_init(&up->receive_queue);
	return 0;
}

static int udp_build_header(struct udp_protocol *up __attribute__ ((unused)), struct nc_buff *ncb)
{
	struct udphdr *uh;
	struct pseudohdr *p;

	uh = ncb->h.uh = ncb_push(ncb, sizeof(struct udphdr));
	if (!uh)
		return -ENOMEM;
	
	uh->source = ncb->nc->unc.lport;
	uh->dest = ncb->nc->unc.fport;
	uh->len = htons(ncb->len);
	uh->check = 0;
	
	p = (struct pseudohdr *)(((__u8 *)uh) - sizeof(struct pseudohdr));
	memset(p, 0, sizeof(*p));

	p->saddr = ncb->nc->unc.laddr;
	p->daddr = ncb->nc->unc.faddr;
	p->tp = IPPROTO_UDP;
	p->len = htonl(ncb->len);

	uh->check = in_csum((__u16 *)p, sizeof(struct pseudohdr) + ncb->len);
	return ip_build_header(ncb);
}

static int udp_process_in(struct netchannel *nc, void *buf, unsigned int size)
{
	struct nc_buff *ncb;
	unsigned int read;

	ncb = ncb_dequeue(&nc->recv_queue);
	if (!ncb)
		return -EAGAIN;

	ulog("%s: size: %u.\n", __func__, ncb->len);
	read = min_t(unsigned int, size, ncb->len);
	memcpy(buf, ncb->head, read);
	ncb_put(ncb);

	return read;
}

static int udp_process_out(struct netchannel *nc, void *buf, unsigned int size)
{
	struct nc_buff *ncb;
	int err;
	struct udp_protocol *up = udp_convert(nc->proto);
	struct nc_route *dst;

	dst = route_get(nc->unc.faddr, nc->unc.laddr);
	if (!dst)
		return -ENODEV;

	ncb = ncb_alloc(size + dst->header_size);
	if (!ncb) {
		err = -ENOMEM;
		goto err_out_put;
	}

	ncb->dst = dst;
	ncb->dst->proto = nc->unc.proto;
	ncb->nc = nc;

	ncb_pull(ncb, dst->header_size);

	memcpy(ncb->head, buf, size);

	err = udp_build_header(up, ncb);
	if (err)
		goto err_out_free;

	err = transmit_data(ncb);
	if (err)
		goto err_out_free;

	route_put(dst);

	return size;

err_out_free:
	ncb_put(ncb);
err_out_put:
	route_put(dst);
	return err;
}

static int udp_destroy(struct netchannel *nc __attribute__ ((unused)))
{
	return 0;
}

struct common_protocol udp_common_protocol = {
	.size		= sizeof(struct udp_protocol),
	.create		= &udp_connect,
	.process_in	= &udp_process_in,
	.process_out	= &udp_process_out,
	.destroy	= &udp_destroy,
};
