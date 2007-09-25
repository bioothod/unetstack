/*
 * 	atcp.c
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
static __u8 atcp_offer_wscale = 14;

static __u32 atcp_max_qlen = 1024*1024;
static __u32 atcp_def_prev_update_ratio = 3;
static unsigned int atcp_default_timeout = 1000;	/* In milliseconds */

struct atcp_cb
{
	__u32			seq, end_seq, ack_seq;
};
#define TCP_NCB_CB(ncb)		((struct atcp_cb *)(ncb->cb))

struct atcp_protocol
{
	struct common_protocol	cproto;

	struct netchannel	*nc;

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
	__u32			ack_sent, ack_missed, ack_missed_bytes;
	int			sent_without_reading;

	struct nc_buff_head	ofo_queue;

	struct nc_buff		*send_head, *last_ncb;
	struct nc_buff_head	retransmit_queue;
	struct ncb_timeval	first_packet_ts;
	__u32			retransmit_timeout;
	__u32			dupack_seq, dupack_num, last_retransmit;

	__u32			seq_read;

	__u32			snd_cwnd, snd_cwnd_bytes, snd_ssthresh, in_flight, in_flight_bytes;
	__u32			prev_update_ratio;
	__u32			max_rwin;

	__u32			qlen;
};

struct state_machine
{
	__u32		state;
	int		(*run)(struct atcp_protocol *, struct nc_buff *);
};

static inline struct atcp_protocol *atcp_convert(struct common_protocol *cproto)
{
	return (struct atcp_protocol *)cproto;
}

static inline __u32 ncb_rwin(struct atcp_protocol *tp, struct nc_buff *ncb)
{
	__u32 rwin = ntohs(ncb->h.th->window);
	return (rwin << tp->rwscale);
}

static inline __u32 tp_rwin(struct atcp_protocol *tp)
{
	__u32 rwin = tp->rcv_wnd;
	return rwin << tp->rwscale;
}

static inline __u32 tp_swin(struct atcp_protocol *tp)
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

static __u32 atcp_time;
static inline __u32 atcp_packet_timestamp(void)
{
	return atcp_time++;
	//return (__u32)get_cycles();
	//return time(NULL);
}

struct atcp_option
{
	__u8		kind, length;
	int		(*callback)(struct atcp_protocol *tp, struct nc_buff *ncb, __u8 *data);
};

struct atcp_option_timestamp
{
	__u8			kind, length;
	__u32			tsval, tsecr;
} __attribute__ ((packed));

struct atcp_option_nop
{
	__u8			kind;
} __attribute__ ((packed));

struct atcp_option_mss
{
	__u8			kind, length;
	__u16			mss;
} __attribute__ ((packed));

struct atcp_option_wscale
{
	__u8			kind, length;
	__u8			wscale;
} __attribute__ ((packed));

#define TCP_OPT_NOP	1
#define TCP_OPT_MSS	2
#define TCP_OPT_WSCALE	3
#define TCP_OPT_TS	8

static int atcp_opt_mss(struct atcp_protocol *tp, struct nc_buff *ncb __attribute__ ((unused)), __u8 *data)
{
	tp->mss = ntohs(((__u16 *)data)[0]);
	ulog("%s: mss: %u.\n", __func__, tp->mss);
	return 0;
}

static int atcp_opt_wscale(struct atcp_protocol *tp, struct nc_buff *ncb __attribute__ ((unused)), __u8 *data)
{
	if ((ncb->h.th->syn) && ((tp->state == TCP_SYN_SENT) || (tp->state == TCP_SYN_SENT))) {
		tp->rwscale = data[0];
		if (tp->rwscale > TCP_MAX_WSCALE)
			tp->rwscale = TCP_MAX_WSCALE;
		tp->swscale = atcp_offer_wscale;
		ulog("%s: rwscale: %u, swscale: %u.\n", __func__, tp->rwscale, tp->swscale);
	}
	return 0;
}

static int atcp_opt_ts(struct atcp_protocol *tp, struct nc_buff *ncb, __u8 *data)
{
	__u32 seq = TCP_NCB_CB(ncb)->seq;
	__u32 end_seq = TCP_NCB_CB(ncb)->end_seq;
	__u32 packet_tsval = ntohl(((__u32 *)data)[0]);

	if (!ncb->h.th->ack)
		return 0;

	/* PAWS check */
	if ((tp->state == TCP_ESTABLISHED) && before(packet_tsval, tp->tsecr)) {
		ulog("%s: PAWS failed: packet: seq: %u, end_seq: %u, tsval: %u, tsecr: %u, host tsval: %u, tsecr: %u.\n",
				__func__, seq, end_seq, packet_tsval, ntohl(((__u32 *)data)[1]), tp->tsval, tp->tsecr);
		return 1;
	}
	
	if (between(tp->ack_sent, seq, end_seq) || (tp->state == TCP_SYN_SENT))
		tp->tsecr = packet_tsval;
	else {
		ulog("%s: ack_sent: %u, seq: %u, end_seq: %u.\n", __func__, tp->ack_sent, seq, end_seq);
	}
	return 0;
}

static struct atcp_option atcp_supported_options[] = {
	[TCP_OPT_NOP] = {.kind = TCP_OPT_NOP, .length = 1},
	[TCP_OPT_MSS] = {.kind = TCP_OPT_MSS, .length = 4, .callback = &atcp_opt_mss},
	[TCP_OPT_WSCALE] = {.kind = TCP_OPT_WSCALE, .length = 3, .callback = &atcp_opt_wscale},
	[TCP_OPT_TS] = {.kind = TCP_OPT_TS, .length = 10, .callback = &atcp_opt_ts},
};

static void get_random_bytes(void *data, unsigned int size)
{
	unsigned int i;
	unsigned char *buf = data;

	for (i=0; i<size; ++i)
		buf[i] = 1 + (int) (255.0 * (rand() / (RAND_MAX + 1.0)));
}

#define TCP_FLAG_SYN	0x1
#define TCP_FLAG_ACK	0x2
#define TCP_FLAG_RST	0x4
#define TCP_FLAG_PSH	0x8
#define TCP_FLAG_FIN	0x10

static inline void atcp_set_state(struct atcp_protocol *tp, __u32 state)
{
	ulog("state change: %u -> %u.\n", tp->state, state);
	tp->state = state;
}

static inline int atcp_ncb_data_size(struct nc_buff *ncb)
{
	return (int)(__u32)(TCP_NCB_CB(ncb)->end_seq - TCP_NCB_CB(ncb)->seq);
}

static inline struct nc_route *netchannel_route_get(struct netchannel *nc)
{
	return route_get(nc->unc.data.daddr, nc->unc.data.saddr);
}

void netchannel_route_put(struct nc_route *dst)
{
	route_put(dst);
}

static int atcp_build_header(struct atcp_protocol *tp, struct nc_buff *ncb, __u32 flags, __u8 doff)
{
	struct tcphdr *th;
	struct pseudohdr *p;
	struct atcp_option_nop *nop;
	struct atcp_option_timestamp *ts;

	nop = (struct atcp_option_nop *)ncb_push(ncb, sizeof(struct atcp_option_nop));
	nop->kind = 1;
	nop = (struct atcp_option_nop *)ncb_push(ncb, sizeof(struct atcp_option_nop));
	nop->kind = 1;

	ts = (struct atcp_option_timestamp *)ncb_push(ncb, sizeof(struct atcp_option_timestamp));
	ts->kind = atcp_supported_options[TCP_OPT_TS].kind;
	ts->length = atcp_supported_options[TCP_OPT_TS].length;
	ts->tsval = htonl(atcp_packet_timestamp());
	ts->tsecr = htonl(tp->tsecr);

	ncb->h.th = th = (struct tcphdr *)ncb_push(ncb, sizeof(struct tcphdr));
	memset(th, 0, sizeof(struct tcphdr));

	th->source = tp->nc->unc.data.sport;
	th->dest = tp->nc->unc.data.dport;
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
	th->urg = 0;
	th->urg_ptr = 0;
	th->window = htons(tp->snd_wnd);

	th->doff = 5 + 3 + doff;

	p = (struct pseudohdr *)(((__u8 *)th) - sizeof(struct pseudohdr));
	memset(p, 0, sizeof(*p));

	p->saddr = ncb->nc->unc.data.saddr;
	p->daddr = ncb->nc->unc.data.daddr;
	p->tp = IPPROTO_TCP;
	p->len = htonl(ncb->len);

	th->check = in_csum((__u16 *)p, sizeof(struct pseudohdr) + ncb->len);

	TCP_NCB_CB(ncb)->seq = tp->snd_nxt;
	TCP_NCB_CB(ncb)->end_seq = tp->snd_nxt + ncb->len - (th->doff<<2);
	TCP_NCB_CB(ncb)->ack_seq = tp->rcv_nxt;

	tp->snd_nxt += th->syn + th->fin + ncb->len - (th->doff<<2);
	tp->ack_sent = tp->rcv_nxt;

	return ip_build_header(ncb);
}

static int atcp_send_data(struct atcp_protocol *tp, struct nc_buff *ncb, __u32 flags, __u8 doff)
{
	int err;

	err = atcp_build_header(tp, ncb, flags, doff);
	if (err)
		return err;
	return transmit_data(ncb);
}

static int atcp_send_bit(struct atcp_protocol *tp, __u32 flags)
{
	struct nc_buff *ncb;
	int err;
	struct nc_route *dst;

	dst = netchannel_route_get(tp->nc);
	if (!dst)
		return -ENODEV;

	ncb = ncb_alloc(dst->header_size);
	if (!ncb) {
		err = -ENOMEM;
		goto err_out_put;
	}
	ncb->dst = dst;
	ncb->nc = tp->nc;

	ncb_pull(ncb, dst->header_size);

	err = atcp_send_data(tp, ncb, flags, 0);
	if (err)
		goto err_out_free;
	
	netchannel_route_put(dst);
	return 0;

err_out_free:
	ncb_put(ncb);
err_out_put:
	netchannel_route_put(dst);
	return err;
}

static int atcp_listen(struct atcp_protocol *tp, struct nc_buff *ncb)
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
		get_random_bytes(&tp->iss, sizeof(tp->iss));

		err = atcp_send_bit(tp, TCP_FLAG_SYN|TCP_FLAG_ACK);
		if (err < 0)
			return err;
		atcp_set_state(tp, TCP_SYN_RECV);
	}

	return 0;
}

static void atcp_cleanup_queue(struct nc_buff_head *head, __u32 *qlen)
{
	struct nc_buff *ncb, *n = ncb_peek(head);

	if (!n)
		return;

	do {
		ncb = n->next;
		ncb_unlink(n, head);
		if (qlen)
			*qlen -= n->len;
		ulog("%s: ncb: %p, head: %p, qlen: %u.\n", __func__, ncb, head, *qlen);
		ncb_put(n);
		n = ncb;
	} while (n != (struct nc_buff *)head);
}

static int atcp_in_slow_start(struct atcp_protocol *tp)
{
	return tp->snd_cwnd * tp->mss <= tp->snd_ssthresh;
}

static int atcp_can_send(struct atcp_protocol *tp, struct nc_buff *ncb)
{
	int can_send = 1;

	can_send = tp->snd_cwnd > tp->in_flight;

	if (can_send)
		can_send = tp->in_flight_bytes < tp_rwin(tp);

	if (can_send && ncb) {
		__u32 end_seq = TCP_NCB_CB(ncb)->end_seq;

		if (ncb->len > tp->mss)
			end_seq = TCP_NCB_CB(ncb)->seq + tp->mss;

		can_send = beforeeq(end_seq, tp->snd_una + tp_swin(tp));
	}

	ulog("%s: swin: %u, rwin: %u, cwnd: %u, in_flight: %u [%u], ssthresh: %u, qlen: %u, ss: %d, can_send: %d.\n", 
			__func__, tp_swin(tp), tp_rwin(tp), tp->snd_cwnd, tp->in_flight, tp->in_flight_bytes, 
			tp->snd_ssthresh, tp->qlen, atcp_in_slow_start(tp), can_send);

	return can_send;
}

static int __atcp_try_to_transmit(struct atcp_protocol *tp, struct nc_buff *ncb)
{
	__u32 sdiff = TCP_NCB_CB(ncb)->end_seq - TCP_NCB_CB(ncb)->seq;

	ncb = ncb_clone(ncb);
	if (!ncb)
		return -ENOMEM;

	if (sdiff) {
		tp->in_flight++;
		tp->in_flight_bytes += sdiff;
	}

	return transmit_data(ncb);
}

static int atcp_try_to_transmit(struct atcp_protocol *tp, struct nc_buff *ncb)
{
	int err = -EAGAIN;

	if (atcp_can_send(tp, ncb))
		err = __atcp_try_to_transmit(tp, ncb);

	if ((err < 0) && (tp->send_head == (struct nc_buff *)&tp->retransmit_queue)) {
		ulog("%s: setting head to %p.\n", __func__, ncb);
		tp->send_head = ncb;
	}
	return err;
}

static int atcp_transmit_queue(struct atcp_protocol *tp)
{
	struct nc_buff *ncb = tp->send_head;
	int err = 0;

	while (ncb && (ncb != (struct nc_buff *)&tp->retransmit_queue)) {
		ulog("%s: ncb: %p, retransmit_queue: %p.\n", __func__, ncb, &tp->retransmit_queue);

		if (!ncb->h.raw || !ncb->nh.raw)
			break;

		if (!atcp_can_send(tp, ncb)) {
			err = -EAGAIN;
			break;
		}

		err = __atcp_try_to_transmit(tp, ncb);
		if (err)
			break;

		ncb = ncb->next;
		ulog("%s: setting head to %p.\n", __func__, ncb);
		tp->send_head = ncb;
	}

	return err;
}

static void atcp_check_retransmit_queue(struct atcp_protocol *tp, __u32 ack)
{
	struct nc_buff *ncb, *n = ncb_peek(&tp->retransmit_queue);
	int removed = 0;

	if (!n)
		goto out;

	do {
		__u32 seq, end_seq;

		seq = TCP_NCB_CB(n)->seq;
		end_seq = TCP_NCB_CB(n)->end_seq;

		if (!seq && !end_seq && n->len)
			break;

		if (after(end_seq, ack))
			break;
		else {
			struct tcphdr *th = n->h.th;
			struct iphdr *iph = n->nh.iph;
			__u32 size;

			if (!iph || !th)
				break;
			
			size = ntohs(iph->tot_len) - (iph->ihl<<2) - (th->doff << 2);

			ncb = n->next;

			tp->in_flight--;
			tp->in_flight_bytes -= size;
			tp->qlen -= size;
			ncb_unlink(n, &tp->retransmit_queue);
			
			if (n == tp->send_head)
				tp->send_head = ncb;

			ulog("%s: ack: %u, snd_una: %u, removing: seq: %u, end_seq: %u, ts: %u.%u, in_flight: %u [%u], dec: %u.\n", 
					__func__, ack, tp->snd_una, seq, end_seq, n->tstamp.off_sec, n->tstamp.off_usec, 
					tp->in_flight, tp->in_flight_bytes, size);
			tp->dupack_seq = tp->last_retransmit = TCP_NCB_CB(ncb)->seq;

			ncb_put(n);
			n = ncb;
			removed++;

			if (n != (struct nc_buff *)&tp->retransmit_queue)
				tp->first_packet_ts = n->tstamp;
		}
	} while (n != (struct nc_buff *)&tp->retransmit_queue);

out:
	ulog("%s: removed: %d, in_flight: %u [%u], cwnd: %u.\n", __func__, removed, tp->in_flight, tp->in_flight_bytes, tp->snd_cwnd);

	if (removed)
		atcp_transmit_queue(tp);
}

static void ncb_queue_order(struct nc_buff *ncb, struct nc_buff_head *head)
{
	struct nc_buff *next = ncb_peek(head);
	unsigned int nseq = TCP_NCB_CB(ncb)->seq;
	unsigned int nend_seq = TCP_NCB_CB(ncb)->end_seq;

	if (!ncb->len)
		return;

	ulog("ofo queue: ncb: %p, seq: %u, end_seq: %u.\n", ncb, nseq, nend_seq);

	if (!next) {
		ncb_get(ncb);
		ncb_queue_tail(head, ncb);
		goto out;
	}

	do {
		unsigned int seq = TCP_NCB_CB(next)->seq;
		unsigned int end_seq = TCP_NCB_CB(next)->end_seq;

		if (beforeeq(seq, nseq) && aftereq(end_seq, nend_seq)) {
			ulog("Collapse 1: seq: %u, end_seq: %u removed by seq: %u, end_seq: %u.\n",
					nseq, nend_seq, seq, end_seq);
			ncb_put(ncb);
			ncb = NULL;
			break;
		}

		if (beforeeq(nseq, seq) && aftereq(nend_seq, end_seq)) {
			struct nc_buff *prev = next->prev;

			ncb_unlink(next, head);

			ulog("Collapse 2: seq: %u, end_seq: %u removed by seq: %u, end_seq: %u.\n",
					seq, end_seq, nseq, nend_seq);

			ncb_put(next);
			if (prev == (struct nc_buff *)head)
				break;
			next = prev;
			seq = TCP_NCB_CB(next)->seq;
			end_seq = TCP_NCB_CB(next)->end_seq;
		}
		if (after(seq, nseq))
			break;
	} while ((next = next->next) != (struct nc_buff *)head);

	if (ncb) {
		ulog("Inserting seq: %u, end_seq: %u.\n", nseq, nend_seq);
		ncb_get(ncb);
		ncb_insert(ncb, next->prev, next, head);
	}
out:
	ulog("ofo dump: ");
	next = (struct nc_buff *)head;
	while ((next = next->next) != (struct nc_buff *)head) {
		ulog("%u - %u, ", TCP_NCB_CB(next)->seq, TCP_NCB_CB(next)->end_seq);
	}
	ulog("\n");
}

static void ncb_queue_check(struct atcp_protocol *tp, struct nc_buff_head *head)
{
	struct nc_buff *next = ncb_peek(head);

	if (!next)
		return;

	do {
		unsigned int seq = TCP_NCB_CB(next)->seq;
		unsigned int end_seq = TCP_NCB_CB(next)->end_seq;

		if (before(tp->rcv_nxt, seq))
			break;

		tp->rcv_nxt = max_t(unsigned int, end_seq, tp->rcv_nxt);
	} while ((next = next->next) != (struct nc_buff *)head);

	ulog("ACKed: rcv_nxt: %u.\n", tp->rcv_nxt);
}

static int atcp_syn_sent(struct atcp_protocol *tp, struct nc_buff *ncb)
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
				atcp_set_state(tp, TCP_CLOSE);
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
			atcp_check_retransmit_queue(tp, ack);
		}

		if (after(tp->snd_una, tp->iss)) {
			atcp_set_state(tp, TCP_ESTABLISHED);
			tp->seq_read = seq + 1;
			return atcp_send_bit(tp, TCP_FLAG_ACK);
		}

		atcp_set_state(tp, TCP_SYN_RECV);
		tp->snd_nxt = tp->iss;
		return atcp_send_bit(tp, TCP_FLAG_ACK|TCP_FLAG_SYN);
	}

	return 0;
}

static int atcp_syn_recv(struct atcp_protocol *tp, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;
	__u32 ack = ntohl(th->ack_seq);

	if (th->rst) {
		atcp_set_state(tp, TCP_CLOSE);
		return 0;
	}

	if (th->ack) {
		if (between(ack, tp->snd_una, tp->snd_nxt)) {
			tp->seq_read = ntohl(th->seq) + 1;
			atcp_set_state(tp, TCP_ESTABLISHED);
			return 0;
		}
	}

	if (th->fin) {
		atcp_set_state(tp, TCP_CLOSE_WAIT);
		return 0;
	}

	return -1;
}

static int atcp_fast_retransmit(struct atcp_protocol *tp)
{
	__u32 seq, end_seq, ack;
	struct nc_buff *ncb = ncb_peek(&tp->retransmit_queue);
	int err;

	if (!ncb)
		return -EINVAL;

	while (ncb && (TCP_NCB_CB(ncb)->seq != tp->last_retransmit)) {
		ncb = ncb->next;
		if (ncb == (struct nc_buff *)&tp->retransmit_queue)
			ncb = NULL;
	}

	if (!ncb) {
		ulog("%s: ncb: NULL, last_retransmit: %u.\n", __func__, tp->last_retransmit);
		return -EINVAL;
	}

	seq = TCP_NCB_CB(ncb)->seq;
	end_seq = TCP_NCB_CB(ncb)->end_seq;
	ack = TCP_NCB_CB(ncb)->ack_seq;

	ncb = ncb_clone(ncb);
	if (!ncb)
		return -ENOMEM;

	err = transmit_data(ncb);
	if (err)
		return err;

	tp->last_retransmit = end_seq;
	ulog("%s: seq: %u, end_seq: %u, ack: %u, dupack_seq: %u, last_retransmit: %u.\n", 
			__func__, seq, end_seq, ack, tp->dupack_seq, tp->last_retransmit);
	return 0;
}

static void atcp_congestion(struct atcp_protocol *tp)
{
	__u32 data_wind = min_t(unsigned int, tp->snd_cwnd*tp->mss, tp_rwin(tp));

	if (tp_rwin(tp) > tp->max_rwin) {
		tp->max_rwin = tp_rwin(tp);
		return;
	}

	tp->dupack_num++;

	if (tp->snd_cwnd > 1) {
		tp->snd_cwnd--;
		tp->snd_cwnd_bytes = tp->mss * tp->snd_cwnd;
		tp->prev_update_ratio = atcp_def_prev_update_ratio;
	}

	atcp_fast_retransmit(tp);

	if (tp->dupack_num >= 3) {
		tp->snd_ssthresh = max_t(unsigned int, tp->mss * 2, data_wind/2);
		if (tp->snd_cwnd > 1) {
			tp->snd_cwnd >>= 1;
			tp->snd_cwnd_bytes = tp->mss * tp->snd_cwnd;
			tp->prev_update_ratio = atcp_def_prev_update_ratio;
		}

		ulog("%s: dupack_seq: %u, dupack_num: %u, cwnd: %u [%u], ssthresh: %u, in_flight: %u [%u], ss: %d, rwin: %u, swin: %u.\n", 
			__func__, tp->dupack_seq, tp->dupack_num, tp->snd_cwnd, tp->snd_cwnd*tp->mss, tp->snd_ssthresh,
			tp->in_flight, tp->in_flight_bytes, atcp_in_slow_start(tp),
			tp_rwin(tp), tp_swin(tp));
		tp->dupack_num = 0;
	}
}

static int atcp_established(struct atcp_protocol *tp, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;
	int err = -EINVAL;
	__u32 seq = TCP_NCB_CB(ncb)->seq;
	__u32 end_seq = TCP_NCB_CB(ncb)->end_seq;
	__u32 ack = TCP_NCB_CB(ncb)->ack_seq;
	__u32 rwin = tp_rwin(tp);

	if (before(seq, tp->rcv_nxt)) {
		err = 0;
		goto out;
	}

	if (after(end_seq, tp->rcv_nxt + rwin)) {
		fprintf(stderr, "%s: 1: seq: %u, size: %u, rcv_nxt: %u, rcv_wnd: %u.\n", 
				__func__, seq, ncb->len, tp->rcv_nxt, rwin);
		goto out;
	}

	if (th->rst)
		goto out;

	ulog("%s: seq: %u, end_seq: %u, ack: %u, snd_una: %u, snd_nxt: %u, snd_wnd: %u, rcv_nxt: %u, rcv_wnd: %u, cwnd: %u in_flight: %u [%u], rwin: %u.\n",
			__func__, seq, end_seq, ack, 
			tp->snd_una, tp->snd_nxt, tp_swin(tp), 
			tp->rcv_nxt, rwin, tp->snd_cwnd, tp->in_flight, tp->in_flight_bytes, tp_rwin(tp));
	ulog("R ack: %u, snd_una: %u, snd_nxt: %u, snd_wnd: %u, rcv_wnd: %u, cwnd: %u in_flight: %u [%u], ss: %d, dnum: %u, can_send: %u.\n",
			ack, tp->snd_una, tp->snd_nxt, tp_swin(tp), 
			rwin, 
			tp->snd_cwnd, tp->in_flight, tp->in_flight_bytes, 
			atcp_in_slow_start(tp), tp->dupack_num, atcp_can_send(tp, NULL));

	if (!ncb->len && beforeeq(ack, tp->snd_una)) {
		printf("%s: duplicate ack: %u, snd_una: %u, snd_nxt: %u, snd_wnd: %u, snd_wl1: %u, snd_wl2: %u.\n",
				__func__, ack, tp->snd_una, tp->snd_nxt, tp_swin(tp), tp->snd_wl1, tp->snd_wl2);
		atcp_congestion(tp);
		return 0;
	} else if (after(ack, tp->snd_nxt)) {
		printf("%s: out of order packet: seq: %u, ack: %u, len: %u, rwin: %u.\n", __func__, seq, ack, ncb->len, rwin);
		err = atcp_send_bit(tp, TCP_FLAG_ACK);
		if (err < 0)
			goto out;
	} else if (between(ack, tp->snd_una, tp->snd_nxt)) {
		__u32 ack_bytes = ack - tp->snd_una;

		tp->dupack_num = 0;

		if (atcp_in_slow_start(tp)) {
			tp->snd_cwnd++;
			tp->snd_cwnd_bytes += ack_bytes;
		} else {
			__u32 update = ack_bytes*ack_bytes/(tp->snd_cwnd_bytes);

			tp->snd_cwnd_bytes += update;
			tp->max_rwin = max_t(__u32, tp->max_rwin, tp_rwin(tp));

			if (tp->snd_cwnd_bytes >= tp->max_rwin*tp->prev_update_ratio) {
				tp->snd_cwnd++;
				tp->snd_cwnd_bytes = tp->snd_cwnd * tp->mss;
				tp->prev_update_ratio++;
			}
		}
		tp->snd_una = ack;
		atcp_check_retransmit_queue(tp, ack);
#if 1
		if (before(tp->snd_wl1, seq) || ((tp->snd_wl1 == seq) && beforeeq(tp->snd_wl2, ack))) {
			ulog("%s: Window update: snd_wnd: %u [%u], new: %u, wl1: %u, seq: %u, wl2: %u, ack: %u.\n",
					__func__, tp->snd_wnd, tp_swin(tp), ntohs(th->window),
					tp->snd_wl1, seq, tp->snd_wl2, ack);
			tp->snd_wnd = ntohs(th->window);
			tp->snd_wl1 = seq;
			tp->snd_wl2 = ack;
		}
#endif
	}

	if (beforeeq(seq, tp->rcv_nxt) && aftereq(end_seq, tp->rcv_nxt)) {
		tp->rcv_nxt = end_seq;
		ncb_queue_check(tp, &tp->ofo_queue);
	} else {
		printf("Out of order: rwin: %u, swin: %u, seq: %u, rcv_nxt: %u, size: %u.\n", 
				rwin, tp_swin(tp), seq, tp->rcv_nxt, ncb->len);
		
		ncb_queue_order(ncb, &tp->ofo_queue);
		atcp_send_bit(tp, TCP_FLAG_ACK);
		/*
		 * Out of order packet.
		 */
		err = 0;
		goto out;
	}

	if (ncb->len) {
		ncb_queue_order(ncb, &tp->ofo_queue);

		tp->ack_missed_bytes += ncb->len;
		if (atcp_in_slow_start(tp) == 1 || tp->ack_missed_bytes >= (__u32)3*tp->mss || ++tp->ack_missed >= 3) {
			tp->ack_missed_bytes = 0;
			tp->ack_missed = 0;
			err = atcp_send_bit(tp, TCP_FLAG_ACK);
			if (err < 0)
				goto out;
		}
	}

	if (th->fin) {
		atcp_set_state(tp, TCP_CLOSE_WAIT);
		err = 0;
	}

	err = ncb->len;
out:
	if (err < 0)
		printf("%s: return: %d.\n", __func__, err);
	return err;
}

static int atcp_fin_wait1(struct atcp_protocol *tp, struct nc_buff *ncb)
{
	int err;
	struct tcphdr *th = ncb->h.th;

	if (th->fin) {
		if (th->ack) {
			/* Start time-wait timer... */
			atcp_set_state(tp, TCP_TIME_WAIT);
		} else
			atcp_set_state(tp, TCP_CLOSING);
		return 0;
	}

	err = atcp_established(tp, ncb);
	if (err < 0)
		return err;
	atcp_set_state(tp, TCP_FIN_WAIT2);
	return 0;
}

static int atcp_fin_wait2(struct atcp_protocol *tp, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;

	if (th->fin) {
		/* Start time-wait timer... */
		return 0;
	}

	return atcp_established(tp, ncb);
}

static int atcp_close_wait(struct atcp_protocol *tp, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;

	if (th->fin)
		return 0;

	return atcp_established(tp, ncb);
}

static int atcp_closing(struct atcp_protocol *tp, struct nc_buff *ncb)
{
	int err;
	struct tcphdr *th = ncb->h.th;

	if (th->fin)
		return 0;

	err = atcp_established(tp, ncb);
	if (err < 0)
		return err;
	atcp_set_state(tp, TCP_TIME_WAIT);
	return 0;
}

static int atcp_last_ack(struct atcp_protocol *tp, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;

	if (th->fin)
		return 0;

	atcp_set_state(tp, TCP_CLOSE);
	return 0;
}

static int atcp_time_wait(struct atcp_protocol *tp, struct nc_buff *ncb __attribute__ ((unused)))
{
	return atcp_send_bit(tp, TCP_FLAG_ACK);
}

static int atcp_close(struct atcp_protocol *tp, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;

	atcp_cleanup_queue(&tp->retransmit_queue, &tp->qlen);
	atcp_cleanup_queue(&tp->ofo_queue, NULL);

	if (!th->rst)
		return -1;
	return 0;
}

static struct state_machine atcp_state_machine[] = {
	{ .state = 0, .run = NULL},
	{ .state = TCP_ESTABLISHED, .run = atcp_established, },
	{ .state = TCP_SYN_SENT, .run = atcp_syn_sent, },
	{ .state = TCP_SYN_RECV, .run = atcp_syn_recv, },
	{ .state = TCP_FIN_WAIT1, .run = atcp_fin_wait1, },
	{ .state = TCP_FIN_WAIT2, .run = atcp_fin_wait2, },
	{ .state = TCP_TIME_WAIT, .run = atcp_time_wait, },
	{ .state = TCP_CLOSE, .run = atcp_close, },
	{ .state = TCP_CLOSE_WAIT, .run = atcp_close_wait, },
	{ .state = TCP_LAST_ACK, .run = atcp_last_ack, },
	{ .state = TCP_LISTEN, .run = atcp_listen, },
	{ .state = TCP_CLOSING, .run = atcp_closing, },
};

#ifdef UDEBUG
static void atcp_work(void *data)
{
	struct atcp_protocol *tp = data;

	ulog("%s: cwnd: %u [%u], ssthresh: %u, ss: %d, in_flight: %u [%u], dupack [%u, %u], rwin: %u, swin: %u, can_send: %u, max_rwin: %u, prev: %u.\n",
			__func__, tp->snd_cwnd, tp->snd_cwnd_bytes, 
			tp->snd_ssthresh, atcp_in_slow_start(tp), 
			tp->in_flight, tp->in_flight_bytes, 
			tp->dupack_num, tp->dupack_seq,
			tp_rwin(tp), tp_swin(tp), atcp_can_send(tp, NULL), tp->max_rwin,
			tp->prev_update_ratio);
}
#endif

static int atcp_init_listen(struct netchannel *nc)
{
	struct atcp_protocol *tp = atcp_convert(nc->proto);
	atcp_set_state(tp, TCP_LISTEN);
	return 0;
}

static int atcp_connect(struct netchannel *nc)
{
	struct atcp_protocol *tp = atcp_convert(nc->proto);
	int err;
	struct nc_buff *ncb;
	struct atcp_option_mss *mss;
	struct atcp_option_wscale *wscale;
	struct atcp_option_nop *nop;
	struct nc_route *dst;
	
	dst = netchannel_route_get(nc);
	if (!dst)
		return -ENODEV;

	ncb = ncb_alloc(dst->header_size);
	if (!ncb) {
		err = -ENOMEM;
		goto err_out_put;
	}
	ncb->dst = dst;
	ncb->nc = nc;

	ncb_pull(ncb, dst->header_size);

	mss = (struct atcp_option_mss *)ncb_push(ncb, sizeof(struct atcp_option_mss));
	mss->kind = TCP_OPT_MSS;
	mss->length = atcp_supported_options[TCP_OPT_MSS].length;
	mss->mss = htons(tp->mss);

	nop = (struct atcp_option_nop *)ncb_push(ncb, sizeof(struct atcp_option_nop));
	nop->kind = 1;
	
	wscale = (struct atcp_option_wscale *)ncb_push(ncb, sizeof(struct atcp_option_wscale));
	wscale->kind = TCP_OPT_WSCALE;
	wscale->length = atcp_supported_options[TCP_OPT_WSCALE].length;
	wscale->wscale = atcp_offer_wscale;

	err = atcp_send_data(tp, ncb, TCP_FLAG_SYN, ncb->len/4);
	if (err < 0)
		goto err_out_free;
	route_put(dst);

	atcp_set_state(tp, TCP_SYN_SENT);
	return 0;

err_out_free:
	ncb_put(ncb);
err_out_put:
	route_put(dst);
	return err;
}

static int atcp_parse_options(struct atcp_protocol *tp, struct nc_buff *ncb)
{
	struct tcphdr *th = ncb->h.th;
	int optsize = (th->doff<<2) - sizeof(struct tcphdr);
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

		if (kind < sizeof(atcp_supported_options)/sizeof(atcp_supported_options[0])) {
			if (optsize < len) {
				err = -EINVAL;
				break;
			}
			if (atcp_supported_options[kind].callback) {
				err = atcp_supported_options[kind].callback(tp, ncb, opt);
				if (err)
					break;
			}
		}
		opt += len - 2;
		optsize -= len;
	}
	return err;
}

static struct nc_buff *atcp_process_in_ncb(struct netchannel *nc, unsigned int *init_len);

static int atcp_out_read(struct netchannel *nc, unsigned int tm)
{
	struct nc_buff *ncb;
	unsigned int init_len;
	int err;

	err = netchannel_recv_raw(nc, tm);

	ncb = atcp_process_in_ncb(nc, &init_len);
	if (ncb) {
		ncb_put(ncb);
		return 1;
	}

	return err;
}

static inline int atcp_retransmit_time(struct atcp_protocol *tp)
{
	return (after(atcp_packet_timestamp(), tp->first_packet_ts.off_sec + tp->retransmit_timeout));
}

static void atcp_retransmit(struct atcp_protocol *tp)
{
	struct nc_buff *first = ncb_peek(&tp->retransmit_queue), *ncb, *nncb;
	int retransmitted = 0;

	if (tp->state == TCP_CLOSE) {
		atcp_cleanup_queue(&tp->retransmit_queue, &tp->qlen);
		return;
	}

	if (!first)
		goto out;

	ulog("%s at %u.\n", __func__, atcp_packet_timestamp());
	ulog("%s: swin: %u, rwin: %u, cwnd: %u, in_flight: %u [%u], ssthresh: %u, qlen: %u, ss: %d, can_send: %d.\n", 
			__func__, tp_swin(tp), tp_rwin(tp), tp->snd_cwnd, tp->in_flight, tp->in_flight_bytes, 
			tp->snd_ssthresh, tp->qlen, atcp_in_slow_start(tp), atcp_can_send(tp, NULL));
#if 1
	tp->in_flight = 0;
	tp->in_flight_bytes = 0;
#endif
	ncb = first;

	do {
		__u32 seq = TCP_NCB_CB(ncb)->seq;
		__u32 end_seq = TCP_NCB_CB(ncb)->end_seq;

		if (before(atcp_packet_timestamp(), ncb->tstamp.off_sec + tp->retransmit_timeout))
			break;
#if 1
		if (!atcp_can_send(tp, ncb))
			break;
#endif
		ulog("%s: ncb: %p, seq: %u, end_seq: %u, ts: %u.%u, time: %u.\n", 
			__func__, ncb, seq, end_seq, ncb->tstamp.off_sec, ncb->tstamp.off_usec, atcp_packet_timestamp());

		if (!seq && !end_seq && ncb->len)
			break;

		nncb = ncb_clone(ncb);
		if (nncb && (transmit_data(nncb) == 0)) {
			ncb->tstamp.off_sec = atcp_packet_timestamp();
			retransmitted++;
		}

		atcp_out_read(tp->nc, 0);
		if (first != ncb_peek(&tp->retransmit_queue))
			break;
	} while ((ncb = ncb->next) != (struct nc_buff *)&tp->retransmit_queue);
out:
	if (retransmitted) {
		ulog("%s: retransmitted: %d, ss: %d, cwnd: %u, in_flight: %u, rwin: %u, in_flight_bytes: %u, ssthresh: %u, swin: %u.\n", 
				__func__, retransmitted, atcp_in_slow_start(tp), tp->snd_cwnd, tp->in_flight,
				tp_rwin(tp), tp->in_flight_bytes, tp->snd_ssthresh, tp_swin(tp));
	}
	return;
}

static int atcp_state_machine_run(struct atcp_protocol *tp, struct nc_buff *ncb)
{
	int err = -EINVAL, broken = 1;
	struct tcphdr *th = ncb->h.th;
	__u16 rwin = ncb_rwin(tp, ncb);
	__u32 seq = TCP_NCB_CB(ncb)->seq;
	__u32 ack = TCP_NCB_CB(ncb)->ack_seq;

	ulog("R %u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u : seq: %u, ack: %u, win: %u [r: %u, s: %u], doff: %u, "
			"s: %u, a: %u, p: %u, r: %u, f: %u, len: %u, state: %u, ncb: %p, snd_una: %u, snd_nxt: %u.\n",
		NIPQUAD(tp->nc->unc.data.saddr), ntohs(tp->nc->unc.data.sport),
		NIPQUAD(tp->nc->unc.data.daddr), ntohs(tp->nc->unc.data.dport),
		seq, ack, ntohs(th->window), rwin, tp_swin(tp), th->doff,
		th->syn, th->ack, th->psh, th->rst, th->fin,
		ncb->len, tp->state, ncb, tp->snd_una, tp->snd_nxt);

	tp->rcv_wnd = ntohs(th->window);

	/* Some kind of header prediction. */
	if ((tp->state == TCP_ESTABLISHED) && (seq == tp->rcv_nxt)) {
		int sz;

		err = atcp_established(tp, ncb);
		if (err < 0)
			goto out;
		sz = err;
		err = atcp_parse_options(tp, ncb);
		if (err >= 0)
			err = sz;
		goto out;
	}
	
	err = atcp_parse_options(tp, ncb);
	if (err < 0)
		goto out;
	if (err > 0)
		return atcp_send_bit(tp, TCP_FLAG_ACK);

	if (tp->state == TCP_SYN_SENT || tp->state == TCP_LISTEN) {
		err = atcp_state_machine[tp->state].run(tp, ncb);
	} else {
		if (!ncb->len && ((!rwin && seq == tp->rcv_nxt) || 
					(rwin && (aftereq(seq, tp->rcv_nxt) && before(seq, tp->rcv_nxt + rwin)))))
				broken = 0;
		else if ((aftereq(seq, tp->rcv_nxt) && before(seq, tp->rcv_nxt + rwin)) &&
					(aftereq(seq, tp->rcv_nxt) && before(seq+ncb->len-1, tp->rcv_nxt + rwin)))
				broken = 0;

		if (broken && !th->rst) {
			ulog("R broken: rwin: %u, swin: %u, seq: %u, rcv_nxt: %u, size: %u.\n", 
					rwin, tp_swin(tp), seq, tp->rcv_nxt, ncb->len);
			return atcp_send_bit(tp, TCP_FLAG_ACK);
		}

		if (th->rst) {
			ulog("R broken rst: rwin: %u, seq: %u, rcv_nxt: %u, size: %u.\n", 
					rwin, seq, tp->rcv_nxt, ncb->len);
			atcp_set_state(tp, TCP_CLOSE);
			err = 0;
			goto out;
		}

		if (th->syn) {
			ulog("R broken syn: rwin: %u, seq: %u, rcv_nxt: %u, size: %u.\n", 
					rwin, seq, tp->rcv_nxt, ncb->len);
			goto out;
		}

		if (!th->ack) {
			fprintf(stderr, "%s: Strange packet.\n", __func__);
			goto out;
		}

		err = atcp_state_machine[tp->state].run(tp, ncb);

		if (between(ack, tp->snd_una, tp->snd_nxt)) {
			tp->snd_una = ack;
			atcp_check_retransmit_queue(tp, ack);
		}

		if (th->fin && seq == tp->rcv_nxt) {
			if (tp->state == TCP_LISTEN || tp->state == TCP_CLOSE)
				return 0;
			tp->rcv_nxt++;
			atcp_send_bit(tp, TCP_FLAG_ACK);
		}
	}

out:
	if (err < 0) {
		__u32 flags = TCP_FLAG_RST;
		if (th->ack) {
			tp->snd_nxt = ntohl(th->ack_seq);
		} else {
			flags |= TCP_FLAG_ACK;
			tp->snd_nxt = 0;
			tp->rcv_nxt = ntohl(th->seq) + ncb->len;
		}
		atcp_set_state(tp, TCP_CLOSE);
		atcp_send_bit(tp, flags);
		atcp_cleanup_queue(&tp->retransmit_queue, &tp->qlen);
	}

	if (atcp_retransmit_time(tp))
		atcp_retransmit(tp);

	return err;
}

static int atcp_read_data(struct atcp_protocol *tp, __u8 *buf, unsigned int size)
{
	struct nc_buff *ncb = ncb_peek(&tp->ofo_queue);
	int read = 0;

	if (!ncb)
		return -EAGAIN;

	ulog("%s: size: %u, seq_read: %u.\n", __func__, size, tp->seq_read);

	while (size && (ncb != (struct nc_buff *)&tp->ofo_queue)) {
		__u32 seq = TCP_NCB_CB(ncb)->seq;
		__u32 end_seq = TCP_NCB_CB(ncb)->end_seq;
		unsigned int sz, data_size, off;
		struct nc_buff *next = ncb->next;

		if (after(tp->seq_read, end_seq)) {
			ulog("Impossible: ncb: seq: %u, end_seq: %u, seq_read: %u.\n",
					seq, end_seq, tp->seq_read);

			ncb_unlink(ncb, &tp->ofo_queue);
			ncb_put(ncb);

			ncb = next;
			continue;
		}

		if (before(tp->seq_read, seq))
			break;

		off = tp->seq_read - seq;
		data_size = ncb->len - off;
		sz = min_t(unsigned int, size, data_size);

		ulog("Copy: seq_read: %u, seq: %u, end_seq: %u, size: %u, off: %u, data_size: %u, sz: %u, read: %d.\n",
				tp->seq_read, seq, end_seq, size, off, data_size, sz, read);

		memcpy(buf, ncb->data+off, sz);

		buf += sz;
		read += sz;
		size -= sz;

		tp->seq_read += sz;

		if (aftereq(tp->seq_read, end_seq)) {
			ulog("Unlinking: ncb: %p, seq: %u, end_seq: %u, seq_read: %u.\n",
					ncb, seq, end_seq, tp->seq_read);

			ncb_unlink(ncb, &tp->ofo_queue);
			ncb_put(ncb);
		}

		ncb = next;
	}

	return read;
}

static struct nc_buff *atcp_process_in_ncb(struct netchannel *nc, unsigned int *init_len)
{
	int err;
	struct nc_buff *ncb;
	struct tcphdr *th;

	ncb = ncb_dequeue(&nc->recv_queue);
	if (!ncb) 
		return NULL;
	ncb->nc = nc;
	
	th = ncb->h.raw = ncb_pull(ncb, sizeof(struct tcphdr));
	if (!ncb->h.raw) {
		ncb_put(ncb);
		return NULL;
	}

	if (th->doff<<2 != sizeof(struct tcphdr))
		ncb_pull(ncb, (th->doff<<2) - sizeof(struct tcphdr));

	TCP_NCB_CB(ncb)->seq = ntohl(th->seq);
	TCP_NCB_CB(ncb)->end_seq = TCP_NCB_CB(ncb)->seq + ncb->len;
	TCP_NCB_CB(ncb)->ack_seq = ntohl(th->ack_seq);

	ulog("\n%s: ncb: %p, data_size: %u.\n", __func__, ncb, ncb->len);

	TCP_NCB_CB(ncb)->seq = ntohl(th->seq);
	TCP_NCB_CB(ncb)->end_seq = TCP_NCB_CB(ncb)->seq + ncb->len;
	TCP_NCB_CB(ncb)->ack_seq = ntohl(th->ack_seq);

	*init_len = ncb->len;

	err = atcp_state_machine_run((struct atcp_protocol *)nc->proto, ncb);
	if (err <= 0) {
		ncb_put(ncb);
		return NULL;
	}

	return ncb;
}

static int atcp_process_in(struct netchannel *nc, void *buf, unsigned int size)
{
	struct atcp_protocol *tp = atcp_convert(nc->proto);
	int err = 0;
	unsigned int read = 0;

	if (tp->state == TCP_CLOSE)
		return -ECONNRESET;

	while (size) {
		if (!ncb_queue_empty(&tp->ofo_queue)) {
			err = atcp_read_data(tp, buf, size);
			if (err > 0) {
				size -= err;
				buf += err;
				read += err;
			}

			if (!size)
				break;
		}

		err = atcp_out_read(nc, atcp_default_timeout);
		if (err != -EAGAIN)
			break;

		if (tp->state != TCP_ESTABLISHED)
			break;
	}

	if (atcp_retransmit_time(tp))
		atcp_retransmit(tp);
	
	return read;
}

static int atcp_create(struct netchannel *nc)
{
	struct atcp_protocol *tp = atcp_convert(nc->proto);

	get_random_bytes(&tp->iss, sizeof(tp->iss));
	tp->snd_wl1 = tp->snd_wl2 = 0;
	tp->snd_wnd = 0xffff;
	tp->snd_nxt = tp->iss;
	tp->rcv_wnd = 0xffff;
	tp->rwscale = 0;
	tp->swscale = 0;
	tp->mss = 1460;
	tp->snd_cwnd = 1;
	tp->snd_cwnd_bytes = tp->mss;
	tp->snd_ssthresh = 0xffff;
	tp->retransmit_timeout = 1;
	tp->prev_update_ratio = atcp_def_prev_update_ratio;
	tp->tsval = atcp_packet_timestamp();
	tp->tsecr = 0;
	tp->nc = nc;
	ncb_queue_init(&tp->retransmit_queue);
	ncb_queue_init(&tp->ofo_queue);
	tp->send_head = (struct nc_buff *)&tp->retransmit_queue;

	if (nc->state == NETCHANNEL_ATCP_LISTEN)
		return atcp_init_listen(nc);
	else if (nc->state == NETCHANNEL_ATCP_CONNECT) {
		int err;

		err = atcp_connect(nc);
		if (err)
			return err;

		atcp_out_read(nc, atcp_default_timeout);

		if (tp->state == TCP_ESTABLISHED)
			return 0;
		return -ECONNRESET;
	}

	return -EINVAL;
}

static int ncb_add_data(struct nc_buff *ncb, void *buf, unsigned int size)
{
	memcpy(ncb->head, buf, size);
	ncb->tail += size;
	ncb->len += size;
	return 0;
}

static int atcp_transmit_combined(struct netchannel *nc, void *buf, unsigned int data_size, int *sent)
{
	struct atcp_protocol *tp = atcp_convert(nc->proto);
	struct nc_buff *ncb;
	int err = 0;
	unsigned int copy, total = 0;

	*sent = 0;
	while (data_size) {
		ncb = tp->last_ncb;
		if (!ncb || !ncb_tailroom(ncb)) {
			ncb = ncb_alloc(tp->mss);
			if (!ncb) {
				err = -ENOMEM;
				goto out;
			}

			ncb->dst = netchannel_route_get(nc);
			if (!ncb->dst) {
				err = -ENODEV;
				goto out;
			}
	
			ncb->nc = nc;

			ncb_pull(ncb, ncb->dst->header_size);
			
			ncb->tail = ncb->head;
			ncb->len = 0;

			tp->last_ncb = ncb;

			tp->qlen += ncb_tailroom(ncb);
			ulog("%s: last ncb: %p, size: %u, tail_len: %u, proto: %u.\n", 
					__func__, ncb, ncb->len, ncb_tailroom(ncb),
					ncb->dst->proto);
		}

		copy = min_t(unsigned int, ncb_tailroom(ncb), data_size);
		err = ncb_add_data(ncb, buf, copy);
		if (err) {
			tp->last_ncb = NULL;
			ncb_put(ncb);
			goto out;
		}
		buf += copy;
		data_size -= copy;
		total += copy;
		
		ulog("%s: ncb: %p, copy: %u, total: %u, data_size: %u, ncb_size: %u, tail_len: %u, snd_next: %u.\n", 
				__func__, ncb, copy, total, data_size, ncb->len, ncb_tailroom(ncb),
				tp->snd_nxt);

		if (!ncb_tailroom(ncb)) {
			err = atcp_build_header(tp, ncb, TCP_FLAG_PSH|TCP_FLAG_ACK, 0);
			if (err) {
				tp->last_ncb = NULL;
				ncb_put(ncb);
				goto out;
			}
			
			ncb_queue_tail(&tp->retransmit_queue, ncb);
			tp->last_ncb = NULL;
			*sent = 1;

			err = atcp_try_to_transmit(tp, ncb);
			if (err) {
				if (err != -EAGAIN)
					goto out;
				break;
			}
		}
	}
	err = total;

out:
	return err;
}

static int atcp_transmit_data(struct netchannel *nc, void *buf, unsigned int data_size)
{
	struct atcp_protocol *tp = atcp_convert(nc->proto);
	struct nc_buff *ncb;
	unsigned int size;
	int err, sent = 0;
	struct nc_route *dst;

	dst = netchannel_route_get(nc);
	if (!dst)
		return -ENODEV;

	while (data_size) {
		size = min_t(unsigned int, tp->mss, dst->header_size + data_size);

		ncb = ncb_alloc(size);
		if (!ncb) {
			sent = -ENOMEM;
			goto err_out_put;
		}
		ncb->dst = dst;
		ncb->nc = nc;

		ncb_pull(ncb, ncb->dst->header_size);
		ncb->tail = ncb->head;
		ncb->len = 0;
		size -= ncb->dst->header_size;

		err = ncb_add_data(ncb, buf, size);
		if (err) {
			ncb_put(ncb);
			sent = err;
			break;
		}

		err = atcp_build_header(tp, ncb, TCP_FLAG_PSH|TCP_FLAG_ACK, 0);
		if (err) {
			ncb_put(ncb);
			sent = err;
			break;
		}

		ncb_queue_tail(&tp->retransmit_queue, ncb);
		tp->qlen += size;
		ulog("%s: queued: ncb: %p, size: %u, qlen: %u, data_size: %u, send_size: %u, tail_size: %u [%p, %p, %p, %p].\n", 
				__func__, ncb, ncb->len, tp->qlen, data_size, size, ncb_tailroom(ncb),
				ncb->head, ncb->data, ncb->tail, ncb->end);

		err = atcp_try_to_transmit(tp, ncb);
		if (err && err != -EAGAIN) {
			sent = err;
			break;
		}

		buf += size;
		data_size -= size;
		sent += size;
	}

err_out_put:
	netchannel_route_put(dst);

	return sent;
}

static int atcp_process_out(struct netchannel *nc, void *buf, unsigned int data_size)
{
	struct atcp_protocol *tp = atcp_convert(nc->proto);
	int ret = 0, sent = 1;

	if (tp->state == TCP_CLOSE)
		return -ECONNRESET;

	if (tp->state == TCP_ESTABLISHED) {
		ret = atcp_transmit_queue(tp);
		if (ret)
			goto out_read;
#if 0
		if (tp->qlen + data_size > atcp_max_qlen) {
			ret = -EAGAIN;
			goto out_read;
		}
#endif
		if (atcp_in_slow_start(tp) || data_size + MAX_HEADER_SIZE >= tp->mss) {
			ret = atcp_transmit_data(nc, buf, data_size);
			atcp_out_read(nc, 0);
		} else {
			ret = atcp_transmit_combined(nc, buf, data_size, &sent);
		}
	}

out_read:
	if ((sent && ++tp->sent_without_reading >= 2) || ret != (signed)data_size) {
		unsigned int tm = atcp_default_timeout;

		if ((tp->state == TCP_ESTABLISHED) && atcp_can_send(tp, NULL))
			tm = 0;
		atcp_out_read(nc, tm);
		tp->sent_without_reading = 0;
	}
	return ret;
}

static int atcp_destroy(struct netchannel *nc)
{
	struct atcp_protocol *tp = atcp_convert(nc->proto);

	if (tp->state == TCP_SYN_RECV ||
			tp->state == TCP_ESTABLISHED || 
			tp->state == TCP_FIN_WAIT1 ||
			tp->state == TCP_FIN_WAIT2 ||
			tp->state == TCP_CLOSE_WAIT)
		atcp_send_bit(tp, TCP_FLAG_RST);

	atcp_set_state(tp, TCP_CLOSE);
	atcp_cleanup_queue(&tp->retransmit_queue, &tp->qlen);
	atcp_cleanup_queue(&tp->ofo_queue, NULL);
	return 0;
}

struct common_protocol atcp_common_protocol = {
	.size		= sizeof(struct atcp_protocol),
	.create		= &atcp_create,
	.process_in	= &atcp_process_in,
	.process_out	= &atcp_process_out,
	.destroy	= &atcp_destroy,
};
