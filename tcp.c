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

typedef signed int __s32;

struct pseudohdr
{
	__u32		saddr, daddr;
	__u8		empty;
	__u8		tp;
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

#define TCP_MAX_WSCALE	14
static __u8 tcp_offer_wscale = 2;

static __u32 tcp_max_qlen = 1024*10;

struct tcp_cb
{
	__u32			seq, seq_end, ack;
};

#define TCP_CB(ncb)		((struct tcp_cb *)(ncb->cb))

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

	__u8			rwscale, swscale;
	__u16			mss;
	__u32			tsval, tsecr;
	__u32			ack_sent;

	struct nc_buff_head	ofo_queue;

	struct nc_buff_head	retransmit_queue;
	__u32			first_packet_ts;
	__u32			retransmit_timeout;

	__u32			seq_read;

	__u32			snd_cwnd, snd_ssthresh, in_flight, cong;

	__u32			qlen;

	struct nc_buff		*combined_start;
};

struct state_machine
{
	__u32		state;
	int		(*run)(struct tcp_protocol *, struct nc_buff *);
};

static inline struct tcp_protocol *tcp_convert(struct common_protocol *cproto)
{
	return (struct tcp_protocol *)cproto;
}

static inline __u32 ncb_rwin(struct tcp_protocol *tp, struct nc_buff *ncb)
{
	__u32 rwin = ntohs(ncb->h.th->window);
	return (rwin << tp->rwscale);
}

static inline __u32 tp_rwin(struct tcp_protocol *tp)
{
	__u32 rwin = tp->rcv_wnd;
	return rwin << tp->rwscale;
}

static inline __u32 tp_swin(struct tcp_protocol *tp)
{
	__u32 swin = tp->snd_wnd;
	return swin << tp->swscale;
}

static inline int before(__u32 seq1, __u32 seq2)
{
        return (__s32)(seq1-seq2) < 0;
}

static inline int beforeeq(__u32 seq1, __u32 seq2)
{
        return (__s32)(seq1-seq2) <= 0;
}

static inline int after(__u32 seq1, __u32 seq2)
{
	return (__s32)(seq2-seq1) < 0;
}

static inline int aftereq(__u32 seq1, __u32 seq2)
{
	return (__s32)(seq2-seq1) <= 0;
}

/* is s2<=s1<=s3 ? */
static inline int between(__u32 seq1, __u32 seq2, __u32 seq3)
{
	return seq3 - seq2 >= seq1 - seq2;
}

struct tcp_option
{
	__u8		kind, length;
	int		(*callback)(struct tcp_protocol *tp, struct nc_buff *ncb, __u8 *data);
};

struct tcp_option_timestamp
{
	__u8			kind, length;
	__u32			tsval, tsecr;
} __attribute__ ((packed));

struct tcp_option_nop
{
	__u8			kind;
} __attribute__ ((packed));

struct tcp_option_mss
{
	__u8			kind, length;
	__u16			mss;
} __attribute__ ((packed));

struct tcp_option_wscale
{
	__u8			kind, length;
	__u8			wscale;
} __attribute__ ((packed));

#define TCP_OPT_NOP	1
#define TCP_OPT_MSS	2
#define TCP_OPT_WSCALE	3
#define TCP_OPT_TS	8

static int tcp_opt_mss(struct tcp_protocol *tp, struct nc_buff *ncb __attribute__ ((unused)), __u8 *data)
{
	tp->mss = ntohs(((__u16 *)data)[0]);
	ulog("%s: mss: %u.\n", __func__, tp->mss);
	return 0;
}

static int tcp_opt_wscale(struct tcp_protocol *tp, struct nc_buff *ncb __attribute__ ((unused)), __u8 *data)
{
	if ((ncb->h.th->syn) && ((tp->state == TCP_SYN_SENT) || (tp->state == TCP_SYN_SENT))) {
		tp->rwscale = data[0];
		if (tp->rwscale > TCP_MAX_WSCALE)
			tp->rwscale = TCP_MAX_WSCALE;
		tp->swscale = tcp_offer_wscale;
		ulog("%s: rwscale: %u, swscale: %u.\n", __func__, tp->rwscale, tp->swscale);
	}
	return 0;
}

static int tcp_opt_ts(struct tcp_protocol *tp, struct nc_buff *ncb, __u8 *data)
{
	__u32 seq = TCP_CB(ncb)->seq;
	__u32 seq_end = TCP_CB(ncb)->seq_end;
	__u32 packet_tsval = ntohl(((__u32 *)data)[0]);

	if (!ncb->h.th->ack)
		return 0;

	/* PAWS check */
	if ((tp->state == TCP_ESTABLISHED) && before(packet_tsval, tp->tsecr)) {
		ulog("%s: PAWS failed: packet: seq: %u, seq_end: %u, tsval: %u, tsecr: %u, host tsval: %u, tsecr: %u.\n",
				__func__, seq, seq_end, packet_tsval, ntohl(((__u32 *)data)[1]), tp->tsval, tp->tsecr);
		return 1;
	}
	
	if (between(tp->ack_sent, seq, seq_end))
		tp->tsecr = packet_tsval;
	return 0;
}

static struct tcp_option tcp_supported_options[] = {
	[TCP_OPT_NOP] = {.kind = TCP_OPT_NOP, .length = 1},
	[TCP_OPT_MSS] = {.kind = TCP_OPT_MSS, .length = 4, .callback = &tcp_opt_mss},
	[TCP_OPT_WSCALE] = {.kind = TCP_OPT_WSCALE, .length = 3, .callback = &tcp_opt_wscale},
	[TCP_OPT_TS] = {.kind = TCP_OPT_TS, .length = 10, .callback = &tcp_opt_ts},
};

#define TCP_FLAG_SYN	0x1
#define TCP_FLAG_ACK	0x2
#define TCP_FLAG_RST	0x4
#define TCP_FLAG_PSH	0x8
#define TCP_FLAG_FIN	0x10

static inline void tcp_set_state(struct tcp_protocol *tp, __u32 state)
{
	ulog("state change: %u -> %u.\n", tp->state, state);
	tp->state = state;
}

static int tcp_build_header(struct tcp_protocol *tp, struct nc_buff *ncb, __u32 flags, __u8 doff)
{
	struct tcphdr *th;
	struct pseudohdr *p;
	struct tcp_option_nop *nop;
	struct tcp_option_timestamp *ts;

	nop = ncb_push(ncb, sizeof(struct tcp_option_nop));
	nop->kind = 1;
	nop = ncb_push(ncb, sizeof(struct tcp_option_nop));
	nop->kind = 1;

	ts = ncb_push(ncb, sizeof(struct tcp_option_timestamp));
	ts->kind = tcp_supported_options[TCP_OPT_TS].kind;
	ts->length = tcp_supported_options[TCP_OPT_TS].length;
	ts->tsval = htonl(tp->tsval);
	ts->tsecr = htonl(tp->tsecr);

	ncb->h.th = th = ncb_push(ncb, sizeof(struct tcphdr));

	th->source = ncb->nc->unc.sport;
	th->dest = ncb->nc->unc.dport;
	th->seq = htonl(tp->snd_nxt);
	th->ack_seq = htonl(tp->rcv_nxt);

	if (flags & TCP_FLAG_SYN)
		th->syn = 1;
	if (flags & TCP_FLAG_ACK)
		th->ack = 1;
	if (flags & TCP_FLAG_PSH)
		th->psh = 1;
	if (flags & TCP_FLAG_RST)
		th->rst = 1;
	if (flags & TCP_FLAG_FIN)
		th->fin = 1;
	th->window = htons(tp->snd_wnd);
	th->doff = 5 + 3 + doff;

	p = (struct pseudohdr *)(((__u8 *)th) - sizeof(struct pseudohdr));
	memset(p, 0, sizeof(*p));

	p->saddr = ncb->nc->unc.src;
	p->daddr = ncb->nc->unc.dst;
	p->tp = IPPROTO_TCP;
	p->len = htonl(ncb->size);

	th->check = in_csum((__u16 *)p, sizeof(struct pseudohdr) + ncb->size);

	TCP_CB(ncb)->seq = tp->snd_nxt;
	TCP_CB(ncb)->seq_end = tp->snd_nxt + ncb->size - 4*th->doff;
	TCP_CB(ncb)->ack = tp->rcv_nxt;

	if (ncb->size - 4*th->doff)
		tp->in_flight++;
	tp->snd_nxt += th->syn + th->fin + ncb->size - 4*th->doff;
	tp->ack_sent = tp->rcv_nxt;

	return ip_build_header(ncb);
}

static int tcp_send_data(struct tcp_protocol *tp, struct nc_buff *ncb, __u32 flags, __u8 doff)
{
	int err;

	err = tcp_build_header(tp, ncb, flags, doff);
	if (err)
		return err;
	return transmit_data(ncb);
}

static int tcp_send_bit(struct tcp_protocol *tp, struct netchannel *nc, __u32 flags)
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

	err = tcp_send_data(tp, ncb, flags, 0);
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

static int tcp_listen(struct tcp_protocol *tp, struct nc_buff *ncb)
{
	int err;
	struct tcphdr *th = ncb->h.th;

	if (th->rst)
		return 0;
	if (th->ack)
		return -1;

	if (th->syn) {
		tp->irs = ntohl(th->seq);
		tp->rcv_nxt = ntohl(th->seq)+1;
		tp->iss = rand();

		err = tcp_send_bit(tp, ncb->nc, TCP_FLAG_SYN|TCP_FLAG_ACK);
		if (err < 0)
			return err;
		tcp_set_state(tp, TCP_SYN_RECV);
	}

	return 0;
}

static void tcp_cleanup_queue(struct nc_buff_head *head, __u32 *qlen)
{
	struct nc_buff *ncb, *n = ncb_peek(head);

	if (!n)
		return;

	do {
		ncb = n->next;
		ncb_unlink(n, head);
		if (qlen)
			*qlen -= n->size;
		ncb_put(n);
		n = ncb;
	} while (n != (struct nc_buff *)head);
}

static void tcp_check_retransmit_queue(struct tcp_protocol *tp, __u32 ack)
{
	struct nc_buff *ncb, *n = ncb_peek(&tp->retransmit_queue);
	int removed = 0;

	if (!n)
		goto out;

	do {
		__u32 seq, seq_end;

		/*
		 * If this header is not setup, then packet was not sent at all yet,
		 * so it can not be acked.
		 */
		if (!n->h.raw)
			break;

		seq = TCP_CB(n)->seq;
		seq_end = TCP_CB(n)->seq_end;

		if (after(seq_end, ack))
			break;
		else {
			tp->in_flight--;
			ulog("%s: ack: %u, snd_una: %u, removing: seq: %u, seq_end: %u, ts: %u, in_flight: %u.\n", 
					__func__, ack, tp->snd_una, seq, seq_end, n->timestamp, tp->in_flight);
			ncb = n->next;
			ncb_unlink(n, &tp->retransmit_queue);
			tp->qlen -= n->size;
			ncb_put(n);
			n = ncb;
			removed++;

			if (n != (struct nc_buff *)&tp->retransmit_queue)
				tp->first_packet_ts = n->timestamp;
		}
	} while (n != (struct nc_buff *)&tp->retransmit_queue);
out:
	ulog("%s: removed: %d, in_flight: %u, cwnd: %u.\n", __func__, removed, tp->in_flight, tp->snd_cwnd);
}

static inline int tcp_retransmit_time(struct tcp_protocol *tp)
{
	return (after(packet_timestamp, tp->first_packet_ts + tp->retransmit_timeout));
}

static void tcp_retransmit(struct tcp_protocol *tp)
{
	struct nc_buff *ncb = ncb_peek(&tp->retransmit_queue);
	int retransmitted = 0;

	if (tp->state == TCP_CLOSE) {
		tcp_cleanup_queue(&tp->retransmit_queue, &tp->qlen);
		return;
	}

	if (!ncb)
		goto out;

	do {
		if (after(packet_timestamp, ncb->timestamp + tp->retransmit_timeout)) {
			__u32 seq = TCP_CB(ncb)->seq;
			__u32 seq_end = TCP_CB(ncb)->seq_end;
			int err;

			ulog("%s: ncb: %p, seq: %u, seq_end: %u, ts: %u, time: %u.\n", 
					__func__, ncb, seq, seq_end, ncb->timestamp, packet_timestamp);
			ncb_get(ncb);
			err = transmit_data(ncb);
			if (err)
				ncb_put(ncb);
			retransmitted++;
		} else
			break;
	} while ((ncb = ncb->next) != (struct nc_buff *)&tp->retransmit_queue);
out:
	return;
	//ulog("%s: retransmitted: %d.\n", __func__, retransmitted);
}

static void ncb_queue_order(struct nc_buff *ncb, struct nc_buff_head *head)
{
	struct nc_buff *next = ncb_peek(head);
	unsigned int nseq = TCP_CB(ncb)->seq;
	unsigned int nseq_end = TCP_CB(ncb)->seq_end;

	ulog("ofo queue: seq: %u, seq_end: %u.\n", nseq, nseq_end);

	if (!next) {
		ncb_get(ncb);
		ncb_queue_tail(head, ncb);
		goto out;
	}

	do {
		unsigned int seq = TCP_CB(next)->seq;
		unsigned int seq_end = TCP_CB(next)->seq_end;

		if (beforeeq(seq, nseq) && aftereq(seq_end, nseq_end)) {
			ulog("Collapse 1: seq: %u, seq_end: %u removed by seq: %u, seq_end: %u.\n",
					nseq, nseq_end, seq, seq_end);
			ncb_put(ncb);
			ncb = NULL;
			break;
		}

		if (beforeeq(nseq, seq) && aftereq(nseq_end, seq_end)) {
			struct nc_buff *prev = next->prev;

			ncb_unlink(next, head);

			ulog("Collapse 2: seq: %u, seq_end: %u removed by seq: %u, seq_end: %u.\n",
					seq, seq_end, nseq, nseq_end);

			ncb_put(next);
			if (prev == (struct nc_buff *)head)
				break;
			next = prev;
			seq = TCP_CB(next)->seq;
			seq_end = TCP_CB(next)->seq_end;
		}
		if (after(seq, nseq))
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
		ulog("%u - %u, ", TCP_CB(next)->seq, TCP_CB(next)->seq_end);
	}
	ulog("\n");
}

static void ncb_queue_check(struct tcp_protocol *tp, struct nc_buff_head *head)
{
	struct nc_buff *next = ncb_peek(head);

	if (!next)
		return;

	do {
		unsigned int seq = TCP_CB(next)->seq;
		unsigned int seq_end = TCP_CB(next)->seq_end;

		if (before(tp->rcv_nxt, seq))
			break;

		tp->rcv_nxt = max_t(unsigned int, seq_end, tp->rcv_nxt);
	} while ((next = next->next) != (struct nc_buff *)head);

	ulog("ACKed: rcv_nxt: %u.\n", tp->rcv_nxt);
}

static int tcp_syn_sent(struct tcp_protocol *tp, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;
	__u32 seq = htonl(th->seq);
	__u32 ack = htonl(th->ack_seq);
#if 0
	ulog("%s: a: %d, s: %d, ack: %u, seq: %u, iss: %u, snd_nxt: %u, snd_una: %u.\n",
			__func__, th->ack, th->syn, ack, seq, tp->iss, tp->snd_nxt, tp->snd_una);
#endif
	if (th->ack) {
		if (beforeeq(ack, tp->iss) || after(ack, tp->snd_nxt))
			return (th->rst)?0:-1;
		if (between(ack, tp->snd_una, tp->snd_nxt)) {
			if (th->rst) {
				tcp_set_state(tp, TCP_CLOSE);
				return 0;
			}
		}
	}

	if (th->rst)
		return 0;

	if (th->syn) {
		tp->rcv_nxt = seq+1;
		tp->irs = seq;
		if (th->ack) {
			tp->snd_una = ack;
			tcp_check_retransmit_queue(tp, ack);
		}

		if (after(tp->snd_una, tp->iss)) {
			tcp_set_state(tp, TCP_ESTABLISHED);
			tp->seq_read = seq + 1;
			return tcp_send_bit(tp, ncb->nc, TCP_FLAG_ACK);
		}

		tcp_set_state(tp, TCP_SYN_RECV);
		tp->snd_nxt = tp->iss;
		return tcp_send_bit(tp, ncb->nc, TCP_FLAG_ACK|TCP_FLAG_SYN);
	}

	return 0;
}

static int tcp_syn_recv(struct tcp_protocol *tp, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;
	__u32 ack = ntohl(th->ack_seq);

	if (th->rst) {
		tcp_set_state(tp, TCP_CLOSE);
		return 0;
	}

	if (th->ack) {
		if (between(ack, tp->snd_una, tp->snd_nxt)) {
			tp->seq_read = ntohl(th->seq) + 1;
			tcp_set_state(tp, TCP_ESTABLISHED);
			return 0;
		}
	}

	if (th->fin) {
		tcp_set_state(tp, TCP_CLOSE_WAIT);
		return 0;
	}

	return -1;
}

static void tcp_process_ack(struct tcp_protocol *tp, struct nc_buff *ncb)
{
	__u32 ack = TCP_CB(ncb)->ack;
	struct nc_buff *n = ncb_peek(&tp->retransmit_queue);

	if (!n)
		return;

	do {
		__u32 ret_seq_end;

		if (!n->h.raw)
			break;
		
		ret_seq_end = TCP_CB(n)->seq_end;
		ncb = n->next;

		if (before(ret_seq_end, ack)) {
			ncb_unlink(n, &tp->retransmit_queue);
			ncb_put(n);
		}
		n = ncb;
	} while (n != (struct nc_buff *)&tp->retransmit_queue);
}

static int tcp_in_slow_start(struct tcp_protocol *tp)
{
	return tp->snd_cwnd * tp->mss <= tp->snd_ssthresh;
}

static void tcp_congestion(struct tcp_protocol *tp)
{
	__u32 min_wind = min_t(unsigned int, tp->snd_cwnd*tp->mss, tp_rwin(tp));
	tp->snd_ssthresh = max_t(unsigned int, tp->mss * 2, min_wind/2);
	if (tp->snd_cwnd == 1)
		return;
	tp->snd_cwnd >>= 1;
	tp->cong++;
}

static int tcp_established(struct tcp_protocol *tp, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;
	int err = -EINVAL;
	__u32 seq = TCP_CB(ncb)->seq;
	__u32 seq_end = TCP_CB(ncb)->seq_end;
	__u32 ack = TCP_CB(ncb)->ack;
	__u32 rwin = tp_rwin(tp);

	if (before(seq, tp->rcv_nxt)) {
		err = 0;
		goto out;
	}

	if (after(seq_end, tp->rcv_nxt + rwin)) {
		ulog("%s: 1: seq: %u, size: %u, rcv_nxt: %u, rcv_wnd: %u.\n", 
				__func__, seq, ncb->size, tp->rcv_nxt, rwin);
		goto out;
	}

	if (th->rst)
		goto out;

	ulog("%s: seq: %u, seq_end: %u, ack: %u, snd_una: %u, snd_nxt: %u, snd_wnd: %u, rcv_nxt: %u, rcv_wnd: %u, cwnd: %u.\n",
			__func__, seq, seq_end, ack, 
			tp->snd_una, tp->snd_nxt, tp_swin(tp), 
			tp->rcv_nxt, rwin, tp->snd_cwnd);

	if (between(ack, tp->snd_una, tp->snd_nxt)) {
		tp->snd_cwnd++;
		tp->snd_una = ack;
		tcp_check_retransmit_queue(tp, ack);
	} else if (before(ack, tp->snd_una)) {
		ulog("%s: duplicate 3 ack: %u, snd_una: %u, snd_nxt: %u, snd_wnd: %u, snd_wl1: %u, snd_wl2: %u.\n",
				__func__, ack, tp->snd_una, tp->snd_nxt, tp_swin(tp), tp->snd_wl1, tp->snd_wl2);
		tcp_congestion(tp);
		tcp_check_retransmit_queue(tp, ack);
		return 0;
	} else if (after(ack, tp->snd_nxt)) {
		err = tcp_send_bit(tp, ncb->nc, TCP_FLAG_ACK);
		if (err < 0)
			goto out;
	}

	if (!ncb->size) {
		tcp_process_ack(tp, ncb);
	} else {
		ncb_queue_order(ncb, &tp->ofo_queue);

		err = tcp_send_bit(tp, ncb->nc, TCP_FLAG_ACK);
		if (err < 0)
			goto out;

	}

	if (beforeeq(seq, tp->rcv_nxt) && aftereq(seq_end, tp->rcv_nxt)) {
		tp->rcv_nxt = seq_end;
		ncb_queue_check(tp, &tp->ofo_queue);
	} else {
		/*
		 * Out of order packet.
		 */
		err = 0;
		goto out;
	}

	if (before(tp->snd_wl1, seq) || ((tp->snd_wl1 == seq) && beforeeq(tp->snd_wl2, ack))) {
		tp->snd_wnd = ntohs(th->window);
		tp->snd_wl1 = seq;
		tp->snd_wl2 = ack;
	}

	if (th->fin) {
		tcp_set_state(tp, TCP_CLOSE_WAIT);
		err = 0;
	}

	err = ncb->size;
out:
	ulog("%s: return: %d.\n", __func__, err);
	return err;
}

static int tcp_fin_wait1(struct tcp_protocol *tp, struct nc_buff *ncb)
{
	int err;
	struct tcphdr *th = ncb->h.th;

	if (th->fin) {
		if (th->ack) {
			/* Start time-wait timer... */
			tcp_set_state(tp, TCP_TIME_WAIT);
		} else
			tcp_set_state(tp, TCP_CLOSING);
		return 0;
	}

	err = tcp_established(tp, ncb);
	if (err < 0)
		return err;
	tcp_set_state(tp, TCP_FIN_WAIT2);
	return 0;
}

static int tcp_fin_wait2(struct tcp_protocol *tp, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;

	if (th->fin) {
		/* Start time-wait timer... */
		return 0;
	}

	return tcp_established(tp, ncb);
}

static int tcp_close_wait(struct tcp_protocol *tp, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;

	if (th->fin)
		return 0;

	return tcp_established(tp, ncb);
}

static int tcp_closing(struct tcp_protocol *tp, struct nc_buff *ncb)
{
	int err;
	struct tcphdr *th = ncb->h.th;

	if (th->fin)
		return 0;

	err = tcp_established(tp, ncb);
	if (err < 0)
		return err;
	tcp_set_state(tp, TCP_TIME_WAIT);
	return 0;
}

static int tcp_last_ack(struct tcp_protocol *tp, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;

	if (th->fin)
		return 0;

	tcp_set_state(tp, TCP_CLOSE);
	return 0;
}

static int tcp_time_wait(struct tcp_protocol *tp, struct nc_buff *ncb)
{
	return tcp_send_bit(tp, ncb->nc, TCP_FLAG_ACK);
}

static int tcp_close(struct tcp_protocol *tp, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;

	tcp_cleanup_queue(&tp->retransmit_queue, &tp->qlen);
	tcp_cleanup_queue(&tp->ofo_queue, NULL);

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

static int tcp_connect(struct netchannel *nc)
{
	struct tcp_protocol *tp = tcp_convert(nc->proto);
	int err;
	struct nc_buff *ncb;
	struct tcp_option_mss *mss;
	struct tcp_option_wscale *wscale;
	struct tcp_option_nop *nop;
	struct nc_route *dst;

	tp->iss = rand();
	tp->snd_wnd = 4096;
	tp->snd_nxt = tp->iss;
	tp->rcv_wnd = 0xffff;
	tp->rwscale = 0;
	tp->swscale = 0;
	tp->snd_cwnd = 1;
	tp->mss = 1460;
	tp->snd_ssthresh = 0xffff;
	tp->retransmit_timeout = 10;
	tp->tsval = time(NULL);
	tp->tsecr = 0;
	ncb_queue_init(&tp->retransmit_queue);
	ncb_queue_init(&tp->ofo_queue);

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
	mss->kind = TCP_OPT_MSS;
	mss->length = tcp_supported_options[TCP_OPT_MSS].length;
	mss->mss = htons(tp->mss);

	nop = ncb_push(ncb, sizeof(struct tcp_option_nop));
	nop->kind = 1;
	
	wscale = ncb_push(ncb, sizeof(struct tcp_option_wscale));
	wscale->kind = TCP_OPT_WSCALE;
	wscale->length = tcp_supported_options[TCP_OPT_WSCALE].length;
	wscale->wscale = tcp_offer_wscale;

	err = tcp_send_data(tp, ncb, TCP_FLAG_SYN, ncb->size/4);
	if (err < 0)
		goto err_out_free;

	route_put(dst);
	tcp_set_state(tp, TCP_SYN_SENT);
	return 0;

err_out_free:
	ncb_put(ncb);
err_out_put:
	route_put(dst);
	return err;
}

static int tcp_parse_options(struct tcp_protocol *tp, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;
	int optsize = th->doff*4 - sizeof(struct tcphdr);
	__u8 *opt = (__u8 *)ncb->h.raw + sizeof(struct tcphdr);
	int err = 0;

	if (optsize < 0)
		return -EINVAL;

	while (optsize) {
		__u8 kind = *opt++;
		__u8 len; 

		if (kind == 1) {
			optsize--;
			continue;
		} else if (kind == 0)
			break;
		else
			len = *opt++;

		//ulog("%s: kind: %u, len: %u, optsize: %d.\n", __func__, kind, len, optsize);

		if (kind < sizeof(tcp_supported_options)/sizeof(tcp_supported_options[0])) {
			if (optsize < len) {
				err = -EINVAL;
				break;
			}
			if (tcp_supported_options[kind].callback) {
				err = tcp_supported_options[kind].callback(tp, ncb, opt);
				if (err)
					break;
			}
		}
		opt += len - 2;
		optsize -= len;
	}
	return err;
}

static int tcp_state_machine_run(struct tcp_protocol *tp, struct nc_buff *ncb)
{
	int err = -EINVAL, broken = 1;
	struct tcphdr *th = ncb->h.th;
	__u16 rwin = ncb_rwin(tp, ncb);
	__u32 seq = TCP_CB(ncb)->seq;
	__u32 ack = TCP_CB(ncb)->ack;

	ulog("R %u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u : seq: %u, ack: %u, win: %u [%u], doff: %u, "
			"s: %u, a: %u, p: %u, r: %u, f: %u, len: %u, state: %u, ncb: %p.\n",
		NIPQUAD(ncb->nc->unc.src), ntohs(ncb->nc->unc.sport),
		NIPQUAD(ncb->nc->unc.dst), ntohs(ncb->nc->unc.dport),
		seq, ack, ntohs(th->window), rwin, th->doff,
		th->syn, th->ack, th->psh, th->rst, th->fin,
		ncb->size, tp->state, ncb);

	tp->rcv_wnd = ntohs(th->window);

	/* Some kind of header prediction. */
	if ((tp->state == TCP_ESTABLISHED) && (seq == tp->rcv_nxt)) {
		int sz;

		err = tcp_established(tp, ncb);
		if (err < 0)
			goto out;
		sz = err;
		err = tcp_parse_options(tp, ncb);
		if (err > 0)
			return tcp_send_bit(tp, ncb->nc, TCP_FLAG_ACK);
		if (err == 0)
			err = sz;
		goto out;
	}

	err = tcp_parse_options(tp, ncb);
	if (err < 0)
		goto out;
	if (err > 0)
		return tcp_send_bit(tp, ncb->nc, TCP_FLAG_ACK);

	if (tp->state == TCP_SYN_SENT) {
		err = tcp_state_machine[tp->state].run(tp, ncb);
	} else {
		if (!ncb->size && ((!rwin && seq == tp->rcv_nxt) || 
					(rwin && (aftereq(seq, tp->rcv_nxt) && before(seq, tp->rcv_nxt + rwin)))))
				broken = 0;
		else if ((aftereq(seq, tp->rcv_nxt) && before(seq, tp->rcv_nxt + rwin)) &&
					(aftereq(seq, tp->rcv_nxt) && before(seq+ncb->size-1, tp->rcv_nxt + rwin)))
				broken = 0;

		if (broken && !th->rst) {
			ulog("R broken: rwin: %u, seq: %u, rcv_nxt: %u, size: %u.\n", 
					rwin, seq, tp->rcv_nxt, ncb->size);
			return tcp_send_bit(tp, ncb->nc, TCP_FLAG_ACK);
		}

		if (th->rst) {
			ulog("R broken rst: rwin: %u, seq: %u, rcv_nxt: %u, size: %u.\n", 
					rwin, seq, tp->rcv_nxt, ncb->size);
			tcp_set_state(tp, TCP_CLOSE);
			err = 0;
			goto out;
		}

		if (th->syn) {
			ulog("R broken syn: rwin: %u, seq: %u, rcv_nxt: %u, size: %u.\n", 
					rwin, seq, tp->rcv_nxt, ncb->size);
			goto out;
		}

		if (!th->ack)
			goto out;

		err = tcp_state_machine[tp->state].run(tp, ncb);

		if (between(ack, tp->snd_una, tp->snd_nxt)) {
			tp->snd_una = ack;
			tcp_check_retransmit_queue(tp, ack);
		}

		if (th->fin && seq == tp->rcv_nxt) {
			if (tp->state == TCP_LISTEN || tp->state == TCP_CLOSE)
				return 0;
			tp->rcv_nxt++;
			tcp_send_bit(tp, ncb->nc, TCP_FLAG_ACK);
		}
	}

out:
#if 0
	ulog("E %u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u : seq: %u, ack: %u, state: %u, err: %d.\n",
		NIPQUAD(ncb->nc->unc.src), ntohs(ncb->nc->unc.sport),
		NIPQUAD(ncb->nc->unc.dst), ntohs(ncb->nc->unc.dport),
		ntohl(th->seq), ntohl(th->ack_seq), tp->state, err);
#endif
	if (err < 0) {
		__u32 flags = TCP_FLAG_RST;
		if (th->ack) {
			tp->snd_nxt = ntohl(th->ack_seq);
		} else {
			flags |= TCP_FLAG_ACK;
			tp->snd_nxt = 0;
			tp->rcv_nxt = ntohl(th->seq) + ncb->size;
		}
		tcp_set_state(tp, TCP_CLOSE);
		tcp_send_bit(tp, ncb->nc, flags);
		tcp_cleanup_queue(&tp->retransmit_queue, &tp->qlen);
	}

	if (tcp_retransmit_time(tp))
		tcp_retransmit(tp);

	return err;
}

static int tcp_read_data(struct tcp_protocol *tp, __u8 *buf, unsigned int size)
{
	struct nc_buff *ncb = ncb_peek(&tp->ofo_queue);
	int read = 0;

	if (!ncb)
		return -EAGAIN;

	ulog("%s: size: %u, seq_read: %u.\n", __func__, size, tp->seq_read);

	while (size && (ncb != (struct nc_buff *)&tp->ofo_queue)) {
		__u32 seq = TCP_CB(ncb)->seq;
		__u32 seq_end = TCP_CB(ncb)->seq_end;
		unsigned int sz, data_size, off;
		struct nc_buff *next = ncb->next;

		if (after(tp->seq_read, seq_end)) {
			ulog("Impossible: ncb: seq: %u, seq_end: %u, seq_read: %u.\n",
					seq, seq_end, tp->seq_read);

			ncb_unlink(ncb, &tp->ofo_queue);
			ncb_put(ncb);

			ncb = next;
			continue;
		}

		if (before(tp->seq_read, seq))
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

		if (aftereq(tp->seq_read, seq)) {
			ulog("Unlinking: ncb: seq: %u, seq_end: %u, seq_read: %u.\n",
					seq, seq_end, tp->seq_read);

			ncb_unlink(ncb, &tp->ofo_queue);
			ncb_put(ncb);
		}

		ncb = next;
	}

	return read;
}

static int tcp_process_in(struct netchannel *nc, void *buf, unsigned int size)
{
	struct tcp_protocol *tp = tcp_convert(nc->proto);
	struct tcphdr *th;
	struct nc_buff *ncb;
	int err = 0;
	unsigned int read = 0;

	while (size) {
		ncb = ncb_dequeue(&nc->recv_queue);
		if (!ncb) 
			break;
		ncb->nc = nc;
		ulog("%s: ncb: %p, size: %u.\n", __func__, ncb, ncb->size);

		th = ncb->h.raw = ncb_pull(ncb, sizeof(struct tcphdr));
		if (!ncb->h.raw)
			break;

		ncb_pull(ncb, th->doff * 4 - sizeof(struct tcphdr));

		TCP_CB(ncb)->seq = ntohl(th->seq);
		TCP_CB(ncb)->seq_end = TCP_CB(ncb)->seq + ncb->size;
		TCP_CB(ncb)->ack = ntohl(th->ack_seq);

		err = tcp_state_machine_run(tp, ncb);
		if (err <= 0) {
			ncb_put(ncb);
			break;
		}

		err = tcp_read_data(tp, buf, size);

		if (err > 0) {
			write(1, buf, err);
			size -= err;
			buf += err;
			read += err;
		}

		ncb_put(ncb);
	}
			
	if (tcp_retransmit_time(tp))
		tcp_retransmit(tp);

	return read;
}

static int tcp_can_send(struct tcp_protocol *tp)
{
	__u32 can_send = tp->snd_cwnd > tp->in_flight;

	ulog("%s: swin: %u, rwin: %u, cwnd: %u, in_flight: %u, ssthresh: %u, qlen: %u, ss: %d.\n", 
			__func__, tp_swin(tp), tp_rwin(tp), tp->snd_cwnd, tp->in_flight, tp->snd_ssthresh, 
			tp->qlen, tcp_in_slow_start(tp));
	return can_send;
}

static int tcp_transmit_combined(struct tcp_protocol *tp)
{
	struct nc_buff *sncb, *ncb, *ncb_end;
	int err = -EINVAL;
	unsigned int left, total;
	void *ptr;

	if (!tp->combined_start)
		goto err_out_exit;

	sncb = ncb_alloc(tp->mss);
	if (!sncb)
		goto err_out_flush;

	ncb_pull(sncb, MAX_HEADER_SIZE);

	left = sncb->size - MAX_HEADER_SIZE;
	total = 0;
	ptr = sncb->head;

	ulog("%s: start: %p.\n", __func__, tp->combined_start);
	
	ncb = ncb_end = tp->combined_start;
	while ((ncb != (struct nc_buff *)&tp->retransmit_queue) && left) {
		if (ncb->size > left)
			break;

		if (!sncb->nc) {
			sncb->nc = ncb->nc;
			sncb->dst = ncb->dst;
			ncb->dst->refcnt++;
		}
		memcpy(ptr, ncb->head, ncb->size);
		ptr += ncb->size;
		left -= ncb->size;
		total += ncb->size;

		ulog("%s: ncb: %p, size: %u, left: %u, total: %u, next: %p, sncb: %p.\n", __func__, ncb, ncb->size, left, total, ncb->next, sncb);

		ncb = ncb_end = ncb->next;
	}

	ulog("%s: total: %u, left: %u, sncb: %p.\n", __func__, total, left, sncb);

	if (!total) {
		err = 0;
		goto err_out_free;
	}
	ncb_trim(sncb, total);
	
	err = tcp_build_header(tp, sncb, TCP_FLAG_PSH|TCP_FLAG_ACK, 0);
	if (err)
		goto err_out_free;

	ncb_insert(sncb, ncb, ncb->next, &tp->retransmit_queue);
	tp->qlen += sncb->size;

	ulog("%s: removing start: %p, last: %p, sncb: %p.\n", __func__, tp->combined_start, ncb_end, sncb);
	ncb = tp->combined_start;
	while (ncb != (struct nc_buff *)&tp->retransmit_queue) {
		struct nc_buff *next = ncb->next;
		ulog("%s: remove: ncb: %p, size: %u, end: %p, qlen: %u.\n", __func__, ncb, ncb->size, ncb_end, tp->qlen);
		tp->qlen -= ncb->size;
		ncb_unlink(ncb, &tp->retransmit_queue);
		ncb_put(ncb);
		if (ncb == ncb_end)
			break;
		ncb = next;
	}
	ulog("%s: transmit, end: %p, head: %p, sncb: %p, dst: %p, ncb: %p.\n", 
			__func__, ncb, &tp->retransmit_queue, sncb, sncb->dst, ncb);
	tp->combined_start = (ncb != (struct nc_buff *)&tp->retransmit_queue)?ncb:NULL;

	err = transmit_data(sncb);
	if (err)
		goto err_out_free;
	return total;

err_out_free:
	ncb_put(sncb);
err_out_flush:
	ncb = tp->combined_start;
	while (ncb != (struct nc_buff *)&tp->retransmit_queue) {
		err = transmit_data(ncb);
		if (err)
			break;
		ncb = ncb->next;
	}
	tp->combined_start = (ncb != (struct nc_buff *)&tp->retransmit_queue)?ncb:NULL;
err_out_exit:
	return err;
}

static int tcp_process_out(struct netchannel *nc, void *buf, unsigned int size)
{
	struct tcp_protocol *tp = tcp_convert(nc->proto);
	struct nc_buff *ncb;
	struct nc_route *dst;
	int err;

	if (tp->state != TCP_ESTABLISHED)
		return -1;
#if 0
	if (tp->qlen + size > tcp_max_qlen)
		return -ENOMEM;
#endif	

	if (!tcp_can_send(tp))
		return -EAGAIN;

	dst = route_get(nc->unc.dst, nc->unc.src);
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

	ncb_get(ncb);
	ncb_queue_tail(&tp->retransmit_queue, ncb);
	tp->qlen += ncb->size;
	ulog("%s: queued: ncb: %p, size: %u, qlen: %u.\n", __func__, ncb, ncb->size, tp->qlen);

	if (tcp_in_slow_start(tp) || tp->mss < MAX_HEADER_SIZE*2 || 1)
		err = tcp_send_data(tp, ncb, TCP_FLAG_PSH|TCP_FLAG_ACK, 0);
	else {
		if (!tp->combined_start)
			tp->combined_start = ncb;

		if (tp->qlen > tp->mss)
			err = tcp_transmit_combined(tp);
		else 
			err = 0;
	}

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

static int tcp_destroy(struct netchannel *nc)
{
	struct tcp_protocol *tp = tcp_convert(nc->proto);

	if (tp->state == TCP_SYN_RECV ||
			tp->state == TCP_ESTABLISHED || 
			tp->state == TCP_FIN_WAIT1 ||
			tp->state == TCP_FIN_WAIT2 ||
			tp->state == TCP_CLOSE_WAIT)
		tcp_send_bit(tp, nc, TCP_FLAG_RST);

	tp->state = TCP_CLOSE;
	return 0;
}

struct common_protocol tcp_protocol = {
	.size		= sizeof(struct tcp_protocol),
	.connect	= &tcp_connect,
	.process_in	= &tcp_process_in,
	.process_out	= &tcp_process_out,
	.destroy	= &tcp_destroy,
};
