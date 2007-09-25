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
#include <sys/time.h>

#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/netchannel.h>

#define PACKET_NAME	"packet"

#ifdef UDEBUG
#define uloga(f, a...) fprintf(stderr, f, ##a)
#else
#define uloga(f, a...)
#endif
#define ulog(f, a...) uloga(f, ##a)
#define ulog_err(f, a...) ulog(f ": %s [%d].\n", ##a, strerror(errno), errno)

#define ulog_info(f, a...) fprintf(stderr, f, ##a)

#define MAX_HEADER_SIZE	100

enum atcp_init_state {
	NETCHANNEL_ATCP_CONNECT = 0,
	NETCHANNEL_ATCP_LISTEN,
};

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
	__u8			proto;
	unsigned int		header_size;
	int			refcnt;
};

struct ncb_timeval
{
	__u32		off_sec;
	__u32		off_usec;
};

/* ncb pointers: 
 * |------|------------------------|-----|
 * data  head                    tail   end
 *
 * [data, head] - headers
 * [head, tail] - data
 */

struct nc_buff
{
	struct nc_buff		*next;
	struct nc_buff		*prev;

	void			*data, *head, *tail, *end;
	unsigned int		len, total_size;

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

	struct ncb_timeval	tstamp;

	__u8			cb[32];
};

extern struct nc_buff *ncb_alloc(unsigned int size);
extern void ncb_free(struct nc_buff *);

extern int transmit_data(struct nc_buff *ncb);
int ip_build_header(struct nc_buff *ncb);
int ip_send_data(struct nc_buff *ncb);

void packet_dump(__u8 *data, unsigned int size);

int packet_ip_process(struct nc_buff *ncb);

static inline void *ncb_push(struct nc_buff *ncb, unsigned int size)
{
	if (ncb->head < ncb->data + size) {
		ulog("%s: head: %p, data: %p, size: %u [%u], req_size: %u.\n",
				__func__, ncb->head, ncb->data, ncb->len, ncb->total_size, size);
		return NULL;
	}
	ncb->head -= size;
	ncb->len += size;
	return ncb->head;
}

static inline void *ncb_pull(struct nc_buff *ncb, unsigned int size)
{
	void *head = ncb->head;
	if (ncb->tail < ncb->head + size) {
		ulog("%s: head: %p, data: %p, size: %u [%u], req_size: %u.\n",
				__func__, ncb->head, ncb->data, ncb->len, ncb->total_size, size);
		return NULL;
	}
	ncb->head += size;
	ncb->len -= size;
	return head;
}

static inline void *ncb_trim(struct nc_buff *ncb, unsigned int size)
{
	if (size > ncb->len) {
		ulog("%s: head: %p, data: %p, size: %u, req_size: %u.\n",
				__func__, ncb->head, ncb->data, ncb->len, size);
		return NULL;
	}
	ncb->tail = ncb->head + size;
	ncb->len = size;
	return ncb->head;
}

static inline struct nc_buff *ncb_get(struct nc_buff *ncb)
{
	ncb->refcnt++;
	return ncb;
}

static inline struct nc_buff *ncb_clone(struct nc_buff *ncb)
{
	return ncb_get(ncb);
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

static inline struct nc_buff *ncb_peek_tail(struct nc_buff_head *list_)
{
	struct nc_buff *list = ((struct nc_buff *)list_)->prev;
	if (list == (struct nc_buff *)list_)
		list = NULL;
	return list;
}

static inline unsigned int ncb_tailroom(struct nc_buff *ncb)
{
	return ncb->end - ncb->tail;
}

static inline void ncb_unlink(struct nc_buff *ncb, struct nc_buff_head *head)
{
	struct nc_buff *prev = ncb->prev;
	struct nc_buff *next = ncb->next;

	prev->next = next;
	next->prev = prev;
	head->qlen--;
}

static inline void ncb_timestamp(struct nc_buff *ncb)
{
	struct timeval tm;

	gettimeofday(&tm, NULL);
	ncb->tstamp.off_sec = tm.tv_sec;
	ncb->tstamp.off_usec = tm.tv_usec;
}

static inline void netchannel_flush_list_head(struct nc_buff_head *list)
{
	struct nc_buff *ncb;
	
	while ((ncb = ncb_dequeue(list)))
		ncb_put(ncb);
}

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define min_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })

extern struct common_protocol atcp_common_protocol;
extern struct common_protocol udp_common_protocol;

struct netchannel;

struct common_protocol
{
	unsigned int		size;

	int 			(*create)(struct netchannel *);
	int 			(*destroy)(struct netchannel *);

	int 			(*process_in)(struct netchannel *, void *, unsigned int);
	int 			(*process_out)(struct netchannel *, void *, unsigned int);
};

struct netchannel
{
	struct nc_buff_head 	recv_queue;
	struct unetchannel	unc;

	unsigned long long	hit;

	int			fd;

	unsigned int		state;

	struct common_protocol	*proto;	/* Must be the last member in the structure */
};

struct netchannel *netchannel_create(struct unetchannel *unc, unsigned int state);
void netchannel_remove(struct netchannel *nc);
int netchannel_bind(struct netchannel *nc);

int netchannel_recv(struct netchannel *nc, void *buf, unsigned int size);
int netchannel_send(struct netchannel *nc, void *buf, unsigned int size);
int netchannel_send_raw(struct nc_buff *ncb);
int netchannel_recv_raw(struct netchannel *nc, unsigned int tm);

void netchannel_setup_unc(struct unetchannel *unc,
		unsigned int laddr, unsigned short lport,
		unsigned int faddr, unsigned short fport,
		unsigned int proto, unsigned int order);

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

extern unsigned long syscall_recv, syscall_send;

#endif /* __SYS_H */
