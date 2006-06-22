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

#define ulog_info(f, a...) fprintf(stderr, f, ##a)

#define MAX_HEADER_SIZE	200

struct nc_buff_head {
	/* These two members must be first. */
	struct nc_buff	*next;
	struct nc_buff	*prev;

	__u32		qlen;
};

struct netchannel;

struct nc_route
{
	__u32			src, dst;
	__u8			edst[ETH_ALEN], esrc[ETH_ALEN];
	__u8			proto;
	unsigned int		header_size;
	int			refcnt;
};

struct nc_buff
{
	struct nc_buff		*next;
	struct nc_buff		*prev;

	void			*data, *head, *tail;
	unsigned int		size, total_size;

	int			refcnt;

	struct netchannel	*nc;

	union {
		struct tcphdr	*th;
		struct udphdr	*uh;
		void		*raw;
	} h;
	
	union {
		struct iphdr	*iph;
		void		*raw;
	} nh;

	struct nc_route		*dst;

	__u32			timestamp;

	__u8			cb[32];
};

extern struct nc_buff *ncb_alloc(unsigned int size);
extern void ncb_free(struct nc_buff *);

extern int transmit_data(struct nc_buff *ncb);
int ip_build_header(struct nc_buff *ncb);
int ip_send_data(struct nc_buff *ncb);
int eth_build_header(struct nc_buff *ncb);

void packet_dump(__u8 *data, unsigned int size);

int packet_ip_process(struct nc_buff *ncb);
int packet_eth_process(void *data, unsigned int size);

static inline void *ncb_push(struct nc_buff *ncb, unsigned int size)
{
	if (ncb->head < ncb->data + size) {
		ulog("%s: head: %p, data: %p, size: %u [%u], req_size: %u.\n",
				__func__, ncb->head, ncb->data, ncb->size, ncb->total_size, size);
		return NULL;
	}
	ncb->head -= size;
	ncb->size += size;
	return ncb->head;
}

static inline void *ncb_pull(struct nc_buff *ncb, unsigned int size)
{
	void *head = ncb->head;
	if (ncb->tail < ncb->head + size) {
		ulog("%s: head: %p, data: %p, size: %u [%u], req_size: %u.\n",
				__func__, ncb->head, ncb->data, ncb->size, ncb->total_size, size);
		return NULL;
	}
	ncb->head += size;
	ncb->size -= size;
	return head;
}

static inline void *ncb_trim(struct nc_buff *ncb, unsigned int size)
{
	if (size > ncb->size) {
		ulog("%s: head: %p, data: %p, size: %u, req_size: %u.\n",
				__func__, ncb->head, ncb->data, ncb->size, size);
		return NULL;
	}
	ncb->tail = ncb->head + size;
	ncb->size = size;
	return ncb->head;
}

static inline struct nc_buff *ncb_get(struct nc_buff *ncb)
{
	ncb->refcnt++;
	return ncb;
}

static inline void ncb_put(struct nc_buff *ncb)
{
	if (ncb->refcnt <= 0)
		ulog("%s: BUG: refcnt: %d.\n", __func__, ncb->refcnt);
	else if (--ncb->refcnt == 0)
		ncb_free(ncb);
}

static inline void ncb_queue_init(struct nc_buff_head *list)
{
	list->prev = list->next = (struct nc_buff *)list;
	list->qlen = 0;
}

static inline int ncb_queue_empty(const struct nc_buff_head *list)
{
	return list->next == (struct nc_buff *)list;
}


static inline void ncb_queue_tail(struct nc_buff_head *list, struct nc_buff *ncb)
{
	struct nc_buff *prev, *next;

	list->qlen++;
	next = (struct nc_buff *)list;
	prev = next->prev;
	ncb->next = next;
	ncb->prev = prev;
	next->prev  = prev->next = ncb;
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

static inline void ncb_insert(struct nc_buff *newsk,
				struct nc_buff *prev, struct nc_buff *next,
				struct nc_buff_head *list)
{
	newsk->next = next;
	newsk->prev = prev;
	next->prev  = prev->next = newsk;
	list->qlen++;
}

static inline struct nc_buff *ncb_peek(struct nc_buff_head *list_)
{
	struct nc_buff *list = ((struct nc_buff *)list_)->next;
	if (list == (struct nc_buff *)list_)
		list = NULL;
	return list;
}

static inline void ncb_unlink(struct nc_buff *ncb, struct nc_buff_head *head)
{
	struct nc_buff *prev = ncb->prev;
	struct nc_buff *next = ncb->next;

	prev->next = next;
	next->prev = prev;
	head->qlen--;
}

static inline void netchannel_flush_list_head(struct nc_buff_head *list)
{
	struct nc_buff *ncb;
	
	while ((ncb = ncb_dequeue(list)))
		ncb_put(ncb);
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

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
	
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

extern struct common_protocol tcp_protocol;
extern struct common_protocol udp_protocol;

struct netchannel;

struct common_protocol
{
	unsigned int		size;

	int 			(*connect)(struct netchannel *);
	int 			(*destroy)(struct netchannel *);

	int 			(*process_in)(struct netchannel *, void *, unsigned int);
	int 			(*process_out)(struct netchannel *, void *, unsigned int);
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

	struct common_protocol	*proto;
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
int netchannel_send(struct netchannel *nc, void *buf, unsigned int size);
int netchannel_connect(struct netchannel *nc);

static inline __u16 in_csum(__u16 *addr, unsigned int len)
{
	unsigned int nleft = len;
	__u16 *w = addr;
	unsigned int sum = 0;
	__u16 answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
						
	if (nleft == 1) {
		*(__u8 *)(&answer) = *(__u8 *)w;
		sum += answer;
	}
							    
	sum = (sum >> 16) + (sum & 0xffff);   /* add hi 16 to low 16 */
	sum += (sum >> 16);                   /* add carry */
	answer = ~sum;                        /* truncate to 16 bits */
	return answer;
}

static inline __u32 num2ip(const __u8 a1, const __u8 a2, const __u8 a3, const __u8 a4)
{
	__u32 r = a1;

	r <<= 8;
	r |= a2;
	r <<= 8;
	r |= a3;
	r <<= 8;
	r |= a4;

	return r;
}

extern struct nc_route *route_get(__u32 dst, __u32 src);
extern void route_put(struct nc_route *);
extern int route_add(struct nc_route *rt);
extern void route_fini(void);
extern int route_init(void);

extern unsigned int packet_timestamp;

#endif /* __SYS_H */
