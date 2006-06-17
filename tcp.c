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
#include <time.h>

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
	__u16			rcv_wup;
	__u32			irs;

	__u32			tsval, tsecr;

	struct nc_buff_head	retransmit_queue;
	struct nc_buff_head	ofo_queue;
	__u32			first_retransmit_tsval;

	__u32			seq_read;
};

struct state_machine
{
	__u32		state;
	int		(*run)(struct common_protocol *, struct nc_buff *);
};

struct tcp_option_timestamp
{
	__u8		kind, length;
	__u32		tsval, tsecr;
} __attribute__ ((packed));

struct tcp_option_nop
{
	__u8		kind;
} __attribute__ ((packed));

struct tcp_option_mss
{
	__u8		kind, length;
	__u16		mss;
} __attribute__ ((packed));


static inline struct tcp_protocol *tcp_convert(struct common_protocol *cproto)
{
	return (struct tcp_protocol *)cproto;
}

enum tcp_flags {
	TCP_FLAG_SYN = 0,
	TCP_FLAG_ACK,
	TCP_FLAG_RST,
	TCP_FLAG_PSH,
	TCP_FLAG_FIN,
};

static inline void tcp_set_state(struct tcp_protocol *proto, __u32 state)
{
	ulog("state change: %u -> %u.\n", proto->state, state);
	proto->state = state;
}

static int tcp_send_data(struct common_protocol *cproto, struct nc_buff *ncb, __u32 flags, __u8 doff)
{
	struct tcp_protocol *proto = tcp_convert(cproto);
	struct tcphdr *th;
	struct pseudohdr *p;
	unsigned int data_size = ncb->size;
	struct tcp_option_nop *nop;
	struct tcp_option_timestamp *ts;

	nop = ncb_push(ncb, sizeof(struct tcp_option_nop));
	nop->kind = 1;
	nop = ncb_push(ncb, sizeof(struct tcp_option_nop));
	nop->kind = 1;

	ts = ncb_push(ncb, sizeof(struct tcp_option_timestamp));
	ts->kind = 8;
	ts->length = 10;
	ts->tsval = htonl(proto->tsval);
	ts->tsecr = htonl(proto->tsecr);

	th = ncb_push(ncb, sizeof(struct tcphdr));

	th->source = ncb->nc->unc.sport;
	th->dest = ncb->nc->unc.dport;
	th->seq = htonl(proto->snd_nxt);
	th->ack_seq = htonl(proto->rcv_nxt);

	if (flags & (1 << TCP_FLAG_SYN))
		th->syn = 1;
	if (flags & (1 << TCP_FLAG_ACK))
		th->ack = 1;
	if (flags & (1 << TCP_FLAG_PSH))
		th->psh = 1;
	if (flags & (1 << TCP_FLAG_RST))
		th->rst = 1;
	if (flags & (1 << TCP_FLAG_FIN))
		th->fin = 1;
	th->window = htons(proto->snd_wnd);
	th->doff = 5 + 3 + doff;

	p = (struct pseudohdr *)(((__u8 *)th) - sizeof(struct pseudohdr));
	memset(p, 0, sizeof(*p));

	p->saddr = ncb->nc->unc.src;
	p->daddr = ncb->nc->unc.dst;
	p->proto = IPPROTO_TCP;
	p->len = htonl(ncb->size);

	th->check = in_csum((__u16 *)p, sizeof(struct pseudohdr) + ncb->size);

	proto->snd_una = proto->snd_nxt;
	proto->snd_nxt += th->syn + th->fin + data_size - doff*4;

	return packet_ip_send(ncb);
}

static int tcp_send_bit(struct common_protocol *cproto, struct netchannel *nc, __u32 flags)
{
	struct nc_buff *ncb;
	int err;
	struct nc_route *dst;

	dst = route_get(nc->unc.dst, nc->unc.src);
	if (!dst)
		return -ENODEV;

	ncb = ncb_alloc(dst->header_size);
	if (!ncb) {
		err = -ENOMEM;
		goto err_out_put;
	}

	ncb->dst = dst;
	ncb->dst->proto = nc->unc.proto;
	ncb->nc = nc;

	ncb_pull(ncb, dst->header_size);

	err = tcp_send_data(cproto, ncb, flags, 0);
	if (err < 0)
		goto err_out_free;
	route_put(dst);

	return 0;

err_out_free:
	ncb_put(ncb);
err_out_put:
	route_put(dst);
	return err;
}

static int tcp_listen(struct common_protocol *cproto, struct nc_buff *ncb)
{
	struct tcp_protocol *proto = tcp_convert(cproto);
	int err;
	struct tcphdr *th = ncb->h.th;
	
	if (th->rst)
		return 0;
	if (th->ack)
		return -1;

	if (th->syn) {
		proto->irs = ntohl(th->seq);
		proto->rcv_nxt = ntohl(th->seq)+1;
		proto->iss = rand();

		err = tcp_send_bit(cproto, ncb->nc, (1<<TCP_FLAG_SYN)|(1<<TCP_FLAG_ACK));
		if (err < 0)
			return err;
		tcp_set_state(proto, TCP_SYN_RECV);
	}

	return 0;
}

static void tcp_cleanup_retransmit_queue(struct tcp_protocol *proto)
{
}

static inline __u32 ncb_seq(struct nc_buff *ncb)
{
	//ulog("%s: ncb: %p, th: %p.\n", __func__, ncb, ncb->h.th);
	return ntohl(ncb->h.th->seq);
}

static void ncb_queue_order(struct nc_buff *ncb, struct nc_buff_head *head)
{
	struct nc_buff *next = ncb_peek(head);
	unsigned int nseq = ncb_seq(ncb);
	unsigned int nseq_end = nseq + ncb->size;
	
	ulog("ofo queue: seq: %u, seq_end: %u.\n", nseq, nseq_end);

	if (!next) {
		ncb_get(ncb);
		ncb_queue_tail(head, ncb);
		goto out;
	}

	do {
		unsigned int seq = ncb_seq(next);
		unsigned int seq_end = seq + next->size;

		if (nseq >= seq && nseq_end <= seq_end) {
			ulog("Collapse 1: seq: %u, seq_end: %u removed by seq: %u, seq_end: %u.\n",
					nseq, nseq_end, seq, seq_end);
			ncb_put(ncb);
			ncb = NULL;
			break;
		}

		if (nseq <= seq && nseq_end >= seq_end) {
			struct nc_buff *prev = next->prev;

			ncb_unlink(next, head);
			
			ulog("Collapse 2: seq: %u, seq_end: %u removed by seq: %u, seq_end: %u.\n",
					seq, seq_end, nseq, nseq_end);

			ncb_put(next);
			if (prev == (struct nc_buff *)head)
				break;
			next = prev;
			seq = ncb_seq(next);
			seq_end = seq + next->size;
		}

		if (seq > nseq)
			break;
	} while ((next = next->next) != (struct nc_buff *)head);

	if (ncb) {
		ulog("Inserting seq: %u, seq_end: %u.\n", nseq, nseq_end);
		ncb_get(ncb);
		ncb_insert(ncb, next->prev, next, head);
	}
out:
	ulog("ofo dump: ");
	next = (struct nc_buff *)head;
	while ((next = next->next) != (struct nc_buff *)head) {
		ulog("%u - %u, ", ncb_seq(next), ncb_seq(next) + next->size);
	}
	ulog("\n");
}

static void ncb_queue_check(struct tcp_protocol *tp, struct nc_buff_head *head)
{
	struct nc_buff *next = ncb_peek(head);

	if (!next)
		return;

	do {
		unsigned int seq = ncb_seq(next);
		unsigned int seq_end = seq + next->size;

		if (tp->rcv_nxt < seq)
			break;
		
		tp->rcv_nxt = max_t(unsigned int, seq_end, tp->rcv_nxt);
	} while ((next = next->next) != (struct nc_buff *)head);

	ulog("ACKed: rcv_nxt: %u.\n", tp->rcv_nxt);
}

static int tcp_syn_sent(struct common_protocol *cproto, struct nc_buff *ncb)
{
	struct tcp_protocol *proto = tcp_convert(cproto);
	struct tcphdr *th = ncb->h.th;
	__u32 seq = htonl(th->seq);
	__u32 ack = htonl(th->ack_seq);
#if 0
	ulog("%s: a: %d, s: %d, ack: %u, seq: %u, iss: %u, snd_nxt: %u, snd_una: %u.\n",
			__func__, th->ack, th->syn, ack, seq, proto->iss, proto->snd_nxt, proto->snd_una);
#endif
	if (th->ack) {
		if (ack <= proto->iss || ack > proto->snd_nxt)
			return (th->rst)?0:-1;
		if (proto->snd_una <= ack && ack <= proto->snd_nxt) {
			if (th->rst) {
				tcp_set_state(proto, TCP_CLOSE);
				return 0;
			}
		}
	}

	if (th->rst)
		return 0;

	if (th->syn) {
		proto->rcv_nxt = seq+1;
		proto->irs = seq;
		if (th->ack) {
			proto->snd_una = ack;
			tcp_cleanup_retransmit_queue(proto);
		}

		if (proto->snd_una > proto->iss) {
			tcp_set_state(proto, TCP_ESTABLISHED);
			proto->seq_read = seq + 1;
			return tcp_send_bit(cproto, ncb->nc, 1<<TCP_FLAG_ACK);
		}

		tcp_set_state(proto, TCP_SYN_RECV);
		proto->snd_nxt = proto->iss;
		return tcp_send_bit(cproto, ncb->nc, (1<<TCP_FLAG_ACK)|(1<<TCP_FLAG_SYN));
	}

	return 0;
}

static int tcp_syn_recv(struct common_protocol *cproto, struct nc_buff *ncb)
{
	struct tcp_protocol *proto = tcp_convert(cproto);
	struct tcphdr *th = ncb->h.th;
	__u32 ack = ntohl(th->ack_seq);

	if (th->rst) {
		tcp_set_state(proto, TCP_CLOSE);
		return 0;
	}

	if (th->ack) {
		if (proto->snd_una <= ack && ack <= proto->snd_nxt) {
			proto->seq_read = ntohl(th->seq) + 1;
			tcp_set_state(proto, TCP_ESTABLISHED);
			return 0;
		}
	}

	if (th->fin) {
		tcp_set_state(proto, TCP_CLOSE_WAIT);
		return 0;
	}
	
	return -1;
}

static int tcp_established(struct common_protocol *cproto, struct nc_buff *ncb)
{
	struct tcp_protocol *proto = tcp_convert(cproto);
	struct tcphdr *th = ncb->h.th;
	int err = -EINVAL;
	__u32 seq = ntohl(th->seq);
	__u32 seq_end = seq + ncb->size;
	__u32 ack = ntohl(th->ack_seq);

	if (seq < proto->rcv_nxt || seq > proto->rcv_nxt + proto->rcv_wnd) {
		ulog("%s: 1: seq: %u, size: %u, rcv_nxt: %u, rcv_wnd: %u.\n", __func__, seq, ncb->size, proto->rcv_nxt, proto->rcv_wnd);
		goto out;
	}

	if (seq + ncb->size < proto->rcv_nxt || seq+ncb->size > proto->rcv_nxt + proto->rcv_wnd) {
		ulog("%s: 2: seq: %u, size: %u, rcv_nxt: %u, rcv_wnd: %u.\n", __func__, seq, ncb->size, proto->rcv_nxt, proto->rcv_wnd);
		goto out;
	}

	if (th->rst)
		goto out;

	ulog("%s: seq: %u, seq_end: %u, ack: %u, snd_una: %u, snd_nxt: %u, snd_wnd: %u, rcv_nxt: %u, rcv_wnd: %u.\n",
			__func__, seq, seq_end, ack, 
			proto->snd_una, proto->snd_nxt, proto->snd_wnd, 
			proto->rcv_nxt, proto->rcv_wnd);

	if (proto->snd_una <= ack && ack <= proto->snd_nxt)
		proto->snd_una = ack;
	else if (ack < proto->snd_una) {
		ulog("%s: duplicate 3 ack: %u, snd_una: %u, snd_nxt: %u, snd_wnd: %u, snd_wl1: %u, snd_wl2: %u.\n",
				__func__, ack, proto->snd_una, proto->snd_nxt, proto->snd_wnd, proto->snd_wl1, proto->snd_wl2);
		return 0;
	} else if (ack > proto->snd_nxt) {
		err = tcp_send_bit(cproto, ncb->nc, 1<<TCP_FLAG_ACK);
		if (err < 0)
			goto out;
	}

	if (ncb->size)
		ncb_queue_order(ncb, &proto->ofo_queue);

	if (seq <= proto->rcv_nxt && seq_end >= proto->rcv_nxt) {
		proto->rcv_nxt = seq_end;
		ncb_queue_check(proto, &proto->ofo_queue);
	} else {
		/*
		 * Out of order packet.
		 */
		err = 0;
		goto out;
	}

	if ((proto->snd_wl1 < seq) || (proto->snd_wl1 == seq && proto->snd_wl2 <= ack)) {
		proto->snd_wnd = ntohs(th->window);
		proto->snd_wl1 = seq;
		proto->snd_wl2 = ack;
	}

	if (th->fin) {
		tcp_set_state(proto, TCP_CLOSE_WAIT);
		err = 0;
	}

	err = tcp_send_bit(cproto, ncb->nc, 1<<TCP_FLAG_ACK);
	if (err < 0)
		goto out;

	return ncb->size;

out:
	return err;
}

static int tcp_fin_wait1(struct common_protocol *cproto, struct nc_buff *ncb)
{
	int err;
	struct tcp_protocol *proto = tcp_convert(cproto);
	struct tcphdr *th = ncb->h.th;
	
	if (th->fin) {
		if (th->ack) {
			/* Start time-wait timer... */
			tcp_set_state(proto, TCP_TIME_WAIT);
		} else
			tcp_set_state(proto, TCP_CLOSING);
		return 0;
	}

	err = tcp_established(cproto, ncb);
	if (err < 0)
		return err;
	tcp_set_state(proto, TCP_FIN_WAIT2);
	return 0;
}

static int tcp_fin_wait2(struct common_protocol *cproto, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;
	
	if (th->fin) {
		/* Start time-wait timer... */
		return 0;
	}

	return tcp_established(cproto, ncb);
}

static int tcp_close_wait(struct common_protocol *cproto, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;

	if (th->fin)
		return 0;

	return tcp_established(cproto, ncb);
}

static int tcp_closing(struct common_protocol *cproto, struct nc_buff *ncb)
{
	int err;
	struct tcp_protocol *proto = tcp_convert(cproto);
	struct tcphdr *th = ncb->h.th;
	
	if (th->fin)
		return 0;

	err = tcp_established(cproto, ncb);
	if (err < 0)
		return err;
	tcp_set_state(proto, TCP_TIME_WAIT);
	return 0;
}

static int tcp_last_ack(struct common_protocol *cproto, struct nc_buff *ncb)
{
	struct tcp_protocol *proto = tcp_convert(cproto);
	struct tcphdr *th = ncb->h.th;
	
	if (th->fin)
		return 0;
	
	tcp_set_state(proto, TCP_CLOSE);
	return 0;
}

static int tcp_time_wait(struct common_protocol *cproto, struct nc_buff *ncb)
{
	return tcp_send_bit(cproto, ncb->nc, 1<<TCP_FLAG_ACK);
}

static int tcp_close(struct common_protocol *cproto, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;

	if (!th->rst)
		return -1;
	return 0;
}

static struct state_machine tcp_state_machine[] = {
	{ .state = 0, .run = NULL},
	{ .state = TCP_ESTABLISHED, .run = tcp_established, },
	{ .state = TCP_SYN_SENT, .run = tcp_syn_sent, },
	{ .state = TCP_SYN_RECV, .run = tcp_syn_recv, },
	{ .state = TCP_FIN_WAIT1, .run = tcp_fin_wait1, },
	{ .state = TCP_FIN_WAIT2, .run = tcp_fin_wait2, },
	{ .state = TCP_TIME_WAIT, .run = tcp_time_wait, },
	{ .state = TCP_CLOSE, .run = tcp_close, },
	{ .state = TCP_CLOSE_WAIT, .run = tcp_close_wait, },
	{ .state = TCP_LAST_ACK, .run = tcp_last_ack, },
	{ .state = TCP_LISTEN, .run = tcp_listen, },
	{ .state = TCP_CLOSING, .run = tcp_closing, },
};

static int tcp_connect(struct common_protocol *cproto, struct netchannel *nc)
{
	struct tcp_protocol *proto = tcp_convert(cproto);
	int err;
	struct nc_buff *ncb;
	struct tcp_option_mss *mss;
	struct nc_route *dst;

	proto->iss = rand();
	proto->snd_wnd = 4096;
	proto->snd_nxt = proto->iss;
	proto->rcv_wnd = 0xffff;
	proto->tsval = time(NULL);
	proto->tsecr = 0;
	ncb_queue_init(&proto->retransmit_queue);
	ncb_queue_init(&proto->ofo_queue);

	dst = route_get(nc->unc.dst, nc->unc.src);
	if (!dst)
		return -ENODEV;

	ncb = ncb_alloc(dst->header_size);
	if (!ncb) {
		err = -ENOMEM;
		goto err_out_put;
	}

	ncb->dst = dst;
	ncb->dst->proto = nc->unc.proto;
	ncb->nc = nc;

	ncb_pull(ncb, dst->header_size);

	mss = ncb_push(ncb, sizeof(struct tcp_option_mss));

	mss->kind = 2;
	mss->length = 4;
	mss->mss = htons(1460);

	err = tcp_send_data(cproto, ncb, 1<<TCP_FLAG_SYN, ncb->size/4);
	if (err < 0)
		goto err_out_free;

	route_put(dst);
	tcp_set_state(proto, TCP_SYN_SENT);
	return 0;

err_out_free:
	ncb_put(ncb);
err_out_put:
	route_put(dst);
	return err;
}

static int tcp_state_machine_run(struct common_protocol *cproto, struct nc_buff *ncb)
{
	struct tcp_protocol *proto = tcp_convert(cproto);
	int err = -EINVAL, broken = 1;
	struct tcphdr *th = ncb->h.th;
	__u16 rwin = ntohs(th->window);
	__u32 seq = htonl(th->seq);
	
	ulog("R %u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u : seq: %u, ack: %u, win: %u, doff: %u, "
			"s: %u, a: %u, p: %u, r: %u, f: %u, len: %u, state: %u.\n",
		NIPQUAD(ncb->nc->unc.src), ntohs(ncb->nc->unc.sport),
		NIPQUAD(ncb->nc->unc.dst), ntohs(ncb->nc->unc.dport),
		ntohl(th->seq), ntohl(th->ack_seq), ntohs(th->window), th->doff,
		th->syn, th->ack, th->psh, th->rst, th->fin,
		ncb->size, proto->state);

	if (proto->state >= sizeof(tcp_state_machine)/sizeof(tcp_state_machine[0])) {
		tcp_set_state(proto, TCP_CLOSE);
		goto out;
	}

	if (proto->state == TCP_SYN_SENT) {
		err = tcp_state_machine[proto->state].run(cproto, ncb);
	} else {
		if (!ncb->size && ((!rwin && seq == proto->rcv_nxt) || 
					(rwin && (seq >= proto->rcv_nxt && seq < proto->rcv_nxt + rwin))))
				broken = 0;
		else if ((seq >= proto->rcv_nxt && seq < proto->rcv_nxt + rwin) &&
					(seq >= proto->rcv_nxt && seq+ncb->size-1 < proto->rcv_nxt + rwin))
				broken = 0;

		if (broken && !th->rst) {
			ulog("R broken: rwin: %u, seq: %u, rcv_nxt: %u, size: %u.\n", 
					rwin, seq, proto->rcv_nxt, ncb->size);
			return tcp_send_bit(cproto, ncb->nc, 1<<TCP_FLAG_ACK);
		}

		if (th->rst) {
			ulog("R broken rst: rwin: %u, seq: %u, rcv_nxt: %u, size: %u.\n", 
					rwin, seq, proto->rcv_nxt, ncb->size);
			tcp_set_state(proto, TCP_CLOSE);
			return 0;
		}

		if (th->syn) {
			ulog("R broken syn: rwin: %u, seq: %u, rcv_nxt: %u, size: %u.\n", 
					rwin, seq, proto->rcv_nxt, ncb->size);
			goto out;
		}

		if (!th->ack)
			return 0;

		err = tcp_state_machine[proto->state].run(cproto, ncb);

		if (th->fin && seq == proto->rcv_nxt) {
			if (proto->state == TCP_LISTEN || proto->state == TCP_CLOSE)
				return 0;
			proto->rcv_nxt++;
			tcp_send_bit(cproto, ncb->nc, 1<<TCP_FLAG_ACK);
		}
	}

out:
#if 0
	ulog("E %u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u : seq: %u, ack: %u, state: %u, err: %d.\n",
		NIPQUAD(ncb->nc->unc.src), ntohs(ncb->nc->unc.sport),
		NIPQUAD(ncb->nc->unc.dst), ntohs(ncb->nc->unc.dport),
		ntohl(th->seq), ntohl(th->ack_seq), proto->state, err);
#endif
	if (err < 0) {
		__u32 flags = 1<<TCP_FLAG_RST;
		if (th->ack) {
			proto->snd_nxt = ntohl(th->ack_seq);
			//proto->rcv_nxt = ntohl(th->seq);
		} else {
			flags |= 1 << TCP_FLAG_ACK;
			proto->snd_nxt = 0;
			proto->rcv_nxt = ntohl(th->seq) + ncb->size;
		}
		tcp_set_state(proto, TCP_CLOSE);
		tcp_send_bit(cproto, ncb->nc, flags);
	}

	return err;
}

static int tcp_process_in(struct common_protocol *cproto, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.raw = ncb_pull(ncb, sizeof(struct tcphdr));
	if (!ncb->h.raw)
		return -EINVAL;
	
	ncb_pull(ncb, th->doff * 4 - sizeof(struct tcphdr));

	return tcp_state_machine_run(cproto, ncb);
}

static int tcp_process_out(struct common_protocol *cproto, struct nc_buff *ncb)
{
	struct tcp_protocol *proto = tcp_convert(cproto);

	if (proto->state != TCP_ESTABLISHED)
		return -1;
	
	//ncb_queue_tail(&proto->retransmit_queue, ncb);

	return tcp_send_data(cproto, ncb, (1<<TCP_FLAG_PSH)|(1<<TCP_FLAG_ACK), 0);
}

static int tcp_read_data(struct common_protocol *cproto, __u8 *buf, unsigned int size)
{
	struct tcp_protocol *tp = tcp_convert(cproto);
	struct nc_buff *ncb = ncb_peek(&tp->ofo_queue);
	int read = 0;

	if (!ncb)
		return -EAGAIN;

	ulog("%s: size: %u, seq_read: %u.\n", __func__, size, tp->seq_read);

	while (size && (ncb != (struct nc_buff *)&tp->ofo_queue)) {
		__u32 seq = ncb_seq(ncb);
		__u32 seq_end = ncb_seq(ncb) + ncb->size;
		unsigned int sz, data_size, off;
		struct nc_buff *next = ncb->next;

		if (tp->seq_read > seq_end) {
			ulog("Impossible: ncb: seq: %u, seq_end: %u, seq_read: %u.\n",
					seq, seq_end, tp->seq_read);

			ncb_unlink(ncb, &tp->ofo_queue);
			ncb_put(ncb);

			ncb = next;
			continue;
		}

		if (tp->seq_read < seq)
			break;

		off = tp->seq_read - seq;
		data_size = ncb->size - off;
		sz = min_t(unsigned int, size, data_size);

		ulog("Copy: seq_read: %u, seq: %u, seq_end: %u, size: %u, off: %u, data_size: %u, sz: %u, read: %d.\n",
				tp->seq_read, seq, seq_end, size, off, data_size, sz, read);

		memcpy(buf, ncb->head + off, sz);

		buf += sz;
		read += sz;

		tp->seq_read += sz;

		if (tp->seq_read >= seq) {
			ulog("Unlinking: ncb: seq: %u, seq_end: %u, seq_read: %u.\n",
					seq, seq_end, tp->seq_read);

			ncb_unlink(ncb, &tp->ofo_queue);
			ncb_put(ncb);
		}

		ncb = next;
	}

	return read;
}

static int tcp_destroy(struct common_protocol *cproto, struct netchannel *nc)
{
	struct tcp_protocol *proto = tcp_convert(cproto);
	
	if (proto->state == TCP_SYN_RECV ||
			proto->state == TCP_ESTABLISHED || 
			proto->state == TCP_FIN_WAIT1 ||
			proto->state == TCP_FIN_WAIT2 ||
			proto->state == TCP_CLOSE_WAIT)
		tcp_send_bit(cproto, nc, 1<<TCP_FLAG_RST);

	proto->state = TCP_CLOSE;
	return 0;
}

struct common_protocol tcp_protocol = {
	.size		= sizeof(struct tcp_protocol),
	.connect	= &tcp_connect,
	.process_in	= &tcp_process_in,
	.process_out	= &tcp_process_out,
	.read_data	= &tcp_read_data,
	.destroy	= &tcp_destroy,
};
