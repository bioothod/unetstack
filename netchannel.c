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

#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/poll.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <signal.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "sys.h"
#include <linux/unistd.h>

#define _syscall1(type,name,type1,arg1) \
type name (type1 arg1) \
{\
	return syscall(__NR_##name, arg1);\
}

_syscall1(int, netchannel_control, void *, arg1);

static void netchannel_dump(struct netchannel *nc, char *str, int err)
{
	ulog("netchannel: %s [%u.%u.%u.%u:%u, %u.%u.%u.%u:%u] -> [%u.%u.%u.%u:%u, %u.%u.%u.%u:%u], "
			"proto: [%u, %u], type: %u, order: %u [%u], err: %d.\n",
			str, 
			NIPQUAD(nc->unc.data.saddr), ntohs(nc->unc.data.sport), NIPQUAD(nc->unc.mask.saddr), ntohs(nc->unc.mask.sport),
			NIPQUAD(nc->unc.data.daddr), ntohs(nc->unc.data.dport), NIPQUAD(nc->unc.mask.daddr), ntohs(nc->unc.mask.dport),
			nc->unc.data.proto, nc->unc.mask.proto, 
			nc->unc.type, nc->unc.memory_limit_order, (1<<nc->unc.memory_limit_order), err);
}

void netchannel_remove(struct netchannel *nc)
{
	close(nc->fd);
	netchannel_dump(nc, "remove", 0);
}

struct netchannel *netchannel_create(struct unetchannel *unc, unsigned int state)
{
	struct unetchannel_control ctl;
	int err;
	struct common_protocol *proto;
	struct netchannel *nc;

	if (unc->data.proto == IPPROTO_TCP)
		proto = &atcp_common_protocol;
	else if (unc->data.proto == IPPROTO_UDP)
		proto = &udp_common_protocol;
	else
		return NULL;

	nc = malloc(sizeof(struct netchannel) + proto->size);
	if (!nc)
		return NULL;

	memset(nc, 0, sizeof(struct netchannel) + proto->size);
	ncb_queue_init(&nc->recv_queue);

	nc->proto = (struct common_protocol *)(nc + 1);
	nc->state = state;

	memcpy(nc->proto, proto, sizeof(struct common_protocol));
	memcpy(&nc->unc, unc, sizeof(struct unetchannel));

	memset(&ctl, 0, sizeof(struct unetchannel_control));

	ctl.unc.mask.saddr = unc->mask.daddr;
	ctl.unc.mask.daddr = unc->mask.saddr;
	ctl.unc.mask.sport = unc->mask.dport;
	ctl.unc.mask.dport = unc->mask.sport;
	
	ctl.unc.data.saddr = unc->data.daddr;
	ctl.unc.data.daddr = unc->data.saddr;
	ctl.unc.data.sport = unc->data.dport;
	ctl.unc.data.dport = unc->data.sport;
	
	ctl.unc.mask.proto = unc->mask.proto;
	ctl.unc.data.proto = unc->data.proto;

	ctl.unc.memory_limit_order = unc->memory_limit_order;
	ctl.unc.type = unc->type;

	ctl.cmd = NETCHANNEL_CREATE;
	err = netchannel_control(&ctl);
	if (err < 0 && errno == EEXIST)
		err = 0;
	else if (err > 0) {
		nc->fd = err;
		err = nc->proto->create(nc);
	}

	netchannel_dump(nc, "create", err);

	if (err) {
		free(nc);
		nc = NULL;
	}

	return nc;
}

extern unsigned long syscall_recv, syscall_send;

int netchannel_recv_raw(struct netchannel *nc, unsigned int tm)
{
	struct nc_buff *ncb;
	int err;
	struct pollfd pfd;

	ncb = ncb_alloc(4096);
	if (!ncb)
		return -ENOMEM;

	pfd.fd = nc->fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	syscall_recv += 1;

	err = poll(&pfd, 1, tm);
	if (err < 0) {
		ulog_err("%s: failed to read", __func__);
		return err;
	}

	if (!(pfd.revents & POLLIN) || !err) {
		ulog("%s: no data.\n", __func__);
		return -EAGAIN;
	}
	
	syscall_recv += 1;

	err = read(nc->fd, ncb->head, ncb->len);
	if (err < 0) {
		ulog_err("%s: failed to read", __func__);
		return err;
	}
	if (err == 0)
		return -EAGAIN;

	ncb_trim(ncb, err);
	ncb->nc = nc;

	err = packet_ip_process(ncb);
	if (err)
		goto err_out_free;

	return 0;

err_out_free:
	ncb_put(ncb);
	return err;
}

int netchannel_send_raw(struct nc_buff *ncb)
{
	struct netchannel *nc = ncb->nc;
	int err;

	//err = write(nc->fd, ncb->data, ncb->len);
	err = write(nc->fd, ncb->head, ncb->len);
	if (err < 0)
		return err;

	syscall_send++;
	return 0;
}

int netchannel_send(struct netchannel *nc, void *buf, unsigned int size)
{
	return nc->proto->process_out(nc, buf, size);
}

int netchannel_recv(struct netchannel *nc, void *buf, unsigned int size)
{
	return nc->proto->process_in(nc, buf, size);
}

void netchannel_setup_unc(struct unetchannel *unc,
		unsigned int saddr, unsigned short sport,
		unsigned int daddr, unsigned short dport,
		unsigned int proto, unsigned int order)
{
	unc->mask.daddr = 0xffffffff;
	unc->mask.saddr = 0xffffffff;
	unc->mask.dport = 0xffff;
	unc->mask.sport = 0xffff;
	unc->mask.proto = 0xff;
	unc->data.daddr = daddr;
	unc->data.saddr = saddr;
	unc->data.dport = dport;
	unc->data.sport = sport;
	unc->data.proto = proto;
	unc->memory_limit_order = order;
	unc->type = NETCHANNEL_COPY_USER;
}
