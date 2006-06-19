/*
 * 	netchannel.c
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
#include <sys/poll.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>

#include <netinet/tcp.h>
#include <netinet/ip.h>

#include "sys.h"

static struct netchannel_cache_head **netchannel_hash_table;
static unsigned int netchannel_hash_order = 8;

static inline unsigned int netchannel_hash(struct unetchannel *unc)
{
	unsigned int h = (unc->dst ^ unc->dport) ^ (unc->src ^ unc->sport);
	h ^= h >> 16;
	h ^= h >> 8;
	h ^= unc->proto;
#if 0
	ulog("%s: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u, proto: %u.\n",
			__func__, NIPQUAD(unc->src), ntohs(unc->sport),
			NIPQUAD(unc->dst), ntohs(unc->dport), unc->proto);
#endif
	return h & ((1 << 2*netchannel_hash_order) - 1);
}

static inline void netchannel_convert_hash(unsigned int hash, unsigned int *col, unsigned int *row)
{
	*row = hash & ((1 << netchannel_hash_order) - 1);
	*col = (hash >> netchannel_hash_order) & ((1 << netchannel_hash_order) - 1);
}

struct netchannel_cache_head *netchannel_bucket(struct unetchannel *unc)
{
	unsigned int hash = netchannel_hash(unc);
	unsigned int col, row;

	netchannel_convert_hash(hash, &col, &row);
	return &netchannel_hash_table[col][row];
}

static inline int netchannel_hash_equal_full(struct unetchannel *unc1, struct unetchannel *unc2)
{
	return (unc1->dport == unc2->dport) && (unc1->dst == unc2->dst) &&
				(unc1->sport == unc2->sport) && (unc1->src == unc2->src) && 
				(unc1->proto == unc2->proto);
}

static struct netchannel *netchannel_check_full(struct unetchannel *unc, struct netchannel_cache_head *bucket)
{
	struct netchannel *nc;
	struct hlist_node *node;
	int found = 0;

	hlist_for_each_entry(nc, node, &bucket->head, node) {
		if (netchannel_hash_equal_full(&nc->unc, unc)) {
			found = 1;
			break;
		}
	}

	return (found)?nc:NULL;
}

int netchannel_queue(struct nc_buff *ncb, struct unetchannel *unc)
{
	struct netchannel *nc;
	struct netchannel_cache_head *bucket = netchannel_bucket(unc);

	if (!bucket)
		return -ENODEV;
	nc = netchannel_check_full(unc, bucket);
	if (!nc)
		return -ENODEV;

	ulog("\n+ %u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u : size: %u.\n",
			NIPQUAD(unc->src), ntohs(unc->sport),
			NIPQUAD(unc->dst), ntohs(unc->dport), ncb->size);

	ncb_queue_tail(&nc->recv_queue, ncb);
	nc->hit++;
	return 0;
}

int netchannel_init(void)
{
	unsigned int i, j, num = (1 << netchannel_hash_order);

	netchannel_hash_table = malloc(num * sizeof(void *));
	if (!netchannel_hash_table)
		return -ENOMEM;

	for (i=0; i<num; ++i) {
		struct netchannel_cache_head *l;

		l = malloc(num * sizeof(struct netchannel_cache_head));
		if (!l)
			break;

		for (j=0; j<num; ++j)
			INIT_HLIST_HEAD(&l[j].head);

		netchannel_hash_table[i] = l;
	}

	if (i != num) {
		num = i;
		for (i=0; i<num; ++i)
			free(netchannel_hash_table[i]);
		return -ENOMEM;
	}

	return 0;
}

void netchannel_fini(void)
{
	unsigned int i, num = (1 << netchannel_hash_order);

	for (i=0; i<num; ++i)
		free(netchannel_hash_table[i]);

	free(netchannel_hash_table);
}

static inline void netchannel_dump_info_unc(struct unetchannel *unc, char *prefix, unsigned long long hit, int err)
{
	__u32 src, dst;
	__u16 sport, dport;

	dst = unc->dst;
	src = unc->src;
	dport = ntohs(unc->dport);
	sport = ntohs(unc->sport);

	ulog("%s %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u, proto: %u, hit: %llu, err: %d.\n",
		prefix, NIPQUAD(src), sport, NIPQUAD(dst), dport, 
		unc->proto, hit, err);
}

struct netchannel *netchannel_create(struct unetchannel *unc)
{
	struct netchannel *nc;
	struct netchannel_cache_head *bucket;
	struct common_protocol *proto = NULL;

	switch (unc->proto) {
		case IPPROTO_UDP:
			proto = &udp_protocol;
			break;
		case IPPROTO_TCP:
			proto = &tcp_protocol;
			break;
		default:
			return NULL;
	}

	bucket = netchannel_bucket(unc);
	if (netchannel_check_full(unc, bucket))
		return NULL;

	nc = malloc(sizeof(struct netchannel) + proto->size);
	if (!nc)
		return NULL;

	nc->proto = (struct common_protocol *)(nc + 1);
	memcpy(nc->proto, proto, sizeof(struct common_protocol));

	ncb_queue_init(&nc->recv_queue);
	memcpy(&nc->unc, unc, sizeof(struct unetchannel));

	hlist_add_head(&nc->node, &bucket->head);

	netchannel_dump_info_unc(unc, "create", 0, 0);

	return nc;
}

void netchannel_remove(struct netchannel *nc)
{
	netchannel_dump_info_unc(&nc->unc, "remove", nc->hit, 0);
	hlist_del(&nc->node);
	free(nc);
}

int netchannel_send(struct netchannel *nc, void *buf, unsigned int size)
{
	struct nc_buff *ncb;
	int err;
	struct nc_route *dst;

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

	err = nc->proto->process_out(nc->proto, ncb);
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

int netchannel_recv(struct netchannel *nc, void *buf, unsigned int size)
{
	struct nc_buff *ncb;
	int err = 0;
	unsigned int read = 0;

	while (size) {
		ncb = ncb_dequeue(&nc->recv_queue);
		if (!ncb)
			break;
		ncb->nc = nc;
		err = nc->proto->process_in(nc->proto, ncb);

		ulog("process_in: err: %d.\n", err);

		if (err <= 0) {
			ncb_put(ncb);
			break;
		}

		err = nc->proto->read_data(nc->proto, buf, size);

		if (err > 0) {
			write(1, buf, err);
			size -= err;
			buf += err;
			read += err;
		}

		ncb_put(ncb);
	}

	return read;
}

int netchannel_connect(struct netchannel *nc)
{
	return nc->proto->connect(nc->proto, nc);
}
