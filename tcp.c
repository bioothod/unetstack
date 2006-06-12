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

struct pseudohdr
{
	__u32		saddr, daddr;
	__u8		empty;
	__u8		proto;
	__u32		len;
} __attribute__ ((packed));

#if 0
enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIME_WAIT,
	TCP_CLOSE,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_LISTEN,
	TCP_CLOSING
};
#endif

struct tcp_protocol
{
	struct common_protocol	cproto;

	__u32			state;

	__u32			snd_una;
	__u32			snd_nxt;
	__u16			snd_wnd;
	__u32			snd_wl1;
	__u32			snd_wl2;
	__u32			iss;
	
	__u32			rcv_nxt;
	__u16			rcv_wnd;
	__u32			rcv_irs;
};

struct state_machine
{
	__u32		state;
	int		(*run)(struct common_protocol *, struct nc_buff *);
};

static inline struct tcp_protocol *tcp_convert(struct common_protocol *proto)
{
	return (struct tcp_protocol *)proto;
}

enum tcp_flags {
	TCP_FLAG_SYN = 0,
	TCP_FLAG_ACK,
	TCP_FLAG_PSH,
};

static int tcp_send_bit(struct common_protocol *cproto, struct netchannel *nc, __u32 flags)
{
	struct tcp_protocol *proto = tcp_convert(cproto);
	int err = -ENOMEM;
	struct tcphdr *th;
	struct nc_buff *ncb;
	unsigned int size = sizeof(struct tcphdr) + sizeof(struct iphdr) + sizeof(struct ether_header);
	struct nc_route dst;
	struct pseudohdr *p;

	ncb = ncb_alloc(size);
	if (!ncb)
		goto err_out_free;

	err = -EINVAL;
	if (!ncb_get(ncb, size))
		goto err_out_free;

	th = ncb_put(ncb, sizeof(struct tcphdr));
	if (!th)
		goto err_out_free;

	th->source = nc->unc.sport;
	th->dest = nc->unc.dport;
	th->seq = htonl(proto->snd_nxt);
	th->ack_seq = htonl(proto->rcv_nxt);

	if (flags & (1 << TCP_FLAG_SYN))
		th->syn = 1;
	if (flags & (1 << TCP_FLAG_ACK))
		th->ack = 1;
	if (flags & (1 << TCP_FLAG_PSH))
		th->psh = 1;
	th->window = htons(proto->snd_wnd);
	th->doff = 5;

	p = (struct pseudohdr *)(((__u8 *)th) - sizeof(struct pseudohdr));
	memset(p, 0, sizeof(*p));
	
	p->saddr = nc->unc.src;
	p->daddr = nc->unc.dst;
	p->proto = IPPROTO_TCP;
	p->len = htonl(ncb->size);
	
	th->check = in_csum((__u16 *)p, sizeof(struct pseudohdr) + ncb->size);

	err = route_get(nc->unc.dst, nc->unc.src, &dst);
	if (err)
		goto err_out_free;

	dst.proto = nc->unc.proto;

	err = packet_ip_send(ncb, &dst);
	if (err)
		goto err_out_free;

	return 0;

err_out_free:
	ncb_free(ncb);
	return err;
}


static int tcp_listen(struct common_protocol *proto, struct nc_buff *ncb)
{
	return -1;
}

static int tcp_syn_sent(struct common_protocol *cproto, struct nc_buff *ncb)
{
	struct tcp_protocol *proto = tcp_convert(cproto);
	int err;
	struct tcphdr *th = ncb->h.th;
	
	err = tcp_send_bit(cproto, ncb->nc, (1<<TCP_FLAG_ACK));
	if (err < 0)
		return err;

	if (th->syn && th->ack)
		proto->state = TCP_ESTABLISHED;
	else if (th->syn)
		proto->state = TCP_SYN_RECV;

	return 0;
}

static int tcp_syn_recv(struct common_protocol *proto, struct nc_buff *ncb)
{
	return -1;
}

static int tcp_established(struct common_protocol *proto, struct nc_buff *ncb)
{
	return -1;
}

static int tcp_fin_wait1(struct common_protocol *proto, struct nc_buff *ncb)
{
	return -1;
}

static int tcp_fin_wait2(struct common_protocol *proto, struct nc_buff *ncb)
{
	return -1;
}

static int tcp_close_wait(struct common_protocol *proto, struct nc_buff *ncb)
{
	return -1;
}

static int tcp_closing(struct common_protocol *proto, struct nc_buff *ncb)
{
	return -1;
}

static int tcp_last_ack(struct common_protocol *proto, struct nc_buff *ncb)
{
	return -1;
}

static int tcp_time_wait(struct common_protocol *proto, struct nc_buff *ncb)
{
	return -1;
}

static int tcp_close(struct common_protocol *proto, struct nc_buff *ncb)
{
	return -1;
}

static struct state_machine tcp_state_machine[] = {
	{ .state = 0, .run = NULL},
	{ .state = TCP_LISTEN, .run = tcp_listen, },
	{ .state = TCP_SYN_SENT, .run = tcp_syn_sent, },
	{ .state = TCP_SYN_RECV, .run = tcp_syn_recv, },
	{ .state = TCP_ESTABLISHED, .run = tcp_established, },
	{ .state = TCP_FIN_WAIT1, .run = tcp_fin_wait1, },
	{ .state = TCP_FIN_WAIT2, .run = tcp_fin_wait2, },
	{ .state = TCP_CLOSE_WAIT, .run = tcp_close_wait, },
	{ .state = TCP_CLOSING, .run = tcp_closing, },
	{ .state = TCP_LAST_ACK, .run = tcp_last_ack, },
	{ .state = TCP_TIME_WAIT, .run = tcp_time_wait, },
	{ .state = TCP_CLOSE, .run = tcp_close, },
};

static int tcp_connect(struct common_protocol *cproto, struct netchannel *nc)
{
	struct tcp_protocol *proto = tcp_convert(cproto);
	int err;
	
	err = tcp_send_bit(cproto, nc, (1<<TCP_FLAG_SYN));
	if (err < 0)
		return err;

	proto->state = TCP_SYN_SENT;
	return 0;
}

static int tcp_state_machine_run(struct common_protocol *cproto, struct nc_buff *ncb)
{
	struct tcp_protocol *proto = tcp_convert(cproto);
	int err = -EINVAL;
	__u32 state_before = proto->state;
	struct tcphdr *th = ncb->h.th;
	
	if (th->rst) {
		proto->state = TCP_CLOSE;
		goto out;
	}

	if (proto->state >= sizeof(tcp_state_machine)/sizeof(tcp_state_machine[0])) {
		proto->state = TCP_CLOSE;
		goto out;
	}

	err = tcp_state_machine[proto->state].run(cproto, ncb);

out:
	ulog("%s: state before: %08x, after: %08x, err: %d.\n", __func__, state_before, proto->state, err);
	return err;
}

static int tcp_process_in(struct common_protocol *cproto, struct netchannel *nc, struct nc_buff *ncb, unsigned int size)
{
	ncb->nc = nc;
	ncb->h.raw = ncb_get(ncb, sizeof(struct tcphdr));
	if (!ncb->h.raw)
		return -EINVAL;

	return tcp_state_machine_run(cproto, ncb);
}

static int tcp_process_out(struct common_protocol *proto, struct netchannel *nc, struct nc_buff *ncb, unsigned int size)
{
	return 0;
}

static int tcp_destroy(struct common_protocol *proto, struct netchannel *nc)
{
	return 0;
}

struct common_protocol tcp_protocol = {
	.size		= sizeof(struct tcp_protocol),
	.connect	= &tcp_connect,
	.process_in	= &tcp_process_in,
	.process_out	= &tcp_process_out,
	.destroy	= &tcp_destroy,
};
