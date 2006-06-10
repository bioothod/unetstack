/*
 * 	sys.h
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

#ifndef __SYS_H
#define __SYS_H

#include <stdio.h>
#include <stdlib.h>

#include <net/ethernet.h>

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;

#define PACKET_NAME	"packet"

#ifdef DEBUG
#define uloga(f, a...) fprintf(stderr, f, ##a)
#else
#define uloga(f, a...)
#endif
#define ulog(f, a...) uloga(f, ##a)
#define ulog_err(f, a...) ulog(f ": %s [%d].\n", ##a, strerror(errno), errno)

struct nc_buff_head {
	/* These two members must be first. */
	struct nc_buff	*next;
	struct nc_buff	*prev;

	__u32		qlen;
};

struct nc_buff
{
	struct nc_buff		*next;
	struct nc_buff		*prev;

	void			*data, *head, *tail;
	unsigned int		size, total_size;
};

struct nc_route
{
	__u32			saddr, daddr;
	__u8			eth_dst[ETH_ALEN], eth_src[ETH_ALEN];
	__u8			proto;
};

extern struct nc_buff *ncb_alloc(unsigned int size);
extern void ncb_free(struct nc_buff *);

extern int packet_ip_send(struct nc_buff *ncb, struct nc_route *dst);
extern int packet_eth_send(struct nc_buff *ncb, struct nc_route *dst);
extern int packet_send(struct nc_buff *ncb);

void packet_dump(__u8 *data, unsigned int size);

int packet_ip_process(struct nc_buff *ncb);
int packet_eth_process(void *data, unsigned int size);

static inline void *ncb_put(struct nc_buff *ncb, unsigned int size)
{
	if (ncb->head - ncb->data < size) {
		ulog("%s: head: %p, data: %p, size: %u, req_size: %u.\n",
				__func__, ncb->head, ncb->data, ncb->size, size);
		return NULL;
	}
	ncb->head -= size;
	ncb->size += size;
	return ncb->head;
}

static inline void *ncb_get(struct nc_buff *ncb, unsigned int size)
{
	void *head = ncb->head;
	if (ncb->tail - ncb->head < size) {
		ulog("%s: head: %p, data: %p, size: %u, req_size: %u.\n",
				__func__, ncb->head, ncb->data, ncb->size, size);
		return NULL;
	}
	ncb->head += size;
	ncb->size -= size;
	return head;
}

static inline void nc_buff_head_init(struct nc_buff_head *list)
{
	list->prev = list->next = (struct nc_buff *)list;
	list->qlen = 0;
}

static inline int ncb_queue_empty(const struct nc_buff_head *list)
{
	return list->next == (struct nc_buff *)list;
}


static inline void ncb_queue_tail(struct nc_buff_head *list, struct nc_buff *newnc)
{
	struct nc_buff *prev, *next;

	list->qlen++;
	next = (struct nc_buff *)list;
	prev = next->prev;
	newnc->next = next;
	newnc->prev = prev;
	next->prev  = prev->next = newnc;
}

static inline struct nc_buff *ncb_dequeue(struct nc_buff_head *list)
{
	struct nc_buff *next, *prev, *result;

	prev = (struct nc_buff *) list;
	next = prev->next;
	result = NULL;
	if (next != prev) {
		result	     = next;
		next	     = next->next;
		list->qlen--;
		next->prev   = prev;
		prev->next   = next;
		result->next = result->prev = NULL;
	}
	return result;
}

static inline void netchannel_flush_list_head(struct nc_buff_head *list)
{
	struct nc_buff *ncb;
	
	while ((ncb = ncb_dequeue(list)))
		ncb_free(ncb);
}

struct hlist_node;

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define min_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })

#define container_of(ptr, type, member) ({			\
        const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define hlist_for_each_entry(tpos, pos, head, member)		 \
	for (pos = (head)->first;					 \
	     pos && ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;
	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

static inline void hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
	n->next = LIST_POISON1;
	n->pprev = LIST_POISON2;
}

#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)

extern struct protocol tcp_protocol;
extern struct protocol udp_protocol;

struct netchannel;

struct protocol
{
	__u32			state;

	int 			(*connect)(struct protocol *, struct netchannel *);
	int 			(*process_in)(struct protocol *, struct netchannel *, struct nc_buff *, unsigned int size);
	int 			(*process_out)(struct protocol *, struct netchannel *, struct nc_buff *, unsigned int size);
	int 			(*destroy)(struct protocol *, struct netchannel *);
};

struct unetchannel 
{
	__u32			src, dst;
	__u16			sport, dport;
	__u8			proto;
};

struct netchannel
{
	struct hlist_node	node;
	struct nc_buff_head 	recv_queue;
	struct unetchannel	unc;

	unsigned long long	hit;

	struct protocol		*proto;
};

struct netchannel_cache_head
{
	struct hlist_head	head;
};

int netchannel_queue(struct nc_buff *ncb, struct unetchannel *unc);
int netchannel_init(void);
void netchannel_fini(void);
struct netchannel *netchannel_create(struct unetchannel *unc);
void netchannel_remove(struct netchannel *nc);
int netchannel_recv(struct netchannel *nc, void *buf, unsigned int size);
int netchannel_connect(struct netchannel *nc);

#endif /* __SYS_H */
