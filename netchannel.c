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

_syscall1(int, netchannel_control, void *, arg1);

static inline void netchannel_dump(struct unetchannel *unc, char *prefix, int err, unsigned int len)
{
	if (err)
		ulog_err("%s %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u, proto: %u, len: %u, copy: %u, state: %u, err: %d",
				prefix, NIPQUAD(unc->laddr), ntohs(unc->lport), NIPQUAD(unc->faddr), ntohs(unc->fport),	
				unc->proto, len, unc->copy, unc->state, err);
	else {
		ulog("%s %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u, proto: %u, len: %u, copy: %u, state: %u, err: %d.\n",
				prefix, NIPQUAD(unc->laddr), ntohs(unc->lport), NIPQUAD(unc->faddr), ntohs(unc->fport),	
				unc->proto, len, unc->copy, unc->state, err);

	}
}

void netchannel_remove(struct netchannel *nc)
{
	close(nc->fd);
	netchannel_dump(&nc->unc, "remove", 0, 0);
}

struct netchannel *netchannel_create(struct unetchannel *unc)
{
	struct unetchannel_control ctl;
	int err;
	struct common_protocol *proto;
	struct netchannel *nc;

	if (unc->proto == IPPROTO_TCP)
		proto = &atcp_common_protocol;
	else if (unc->proto == IPPROTO_UDP)
		proto = &udp_common_protocol;
	else
		return NULL;

	nc = malloc(sizeof(struct netchannel) + proto->size);
	if (!nc)
		return NULL;

	memset(nc, 0, sizeof(struct netchannel) + proto->size);
	ncb_queue_init(&nc->recv_queue);

	nc->proto = (struct common_protocol *)(nc + 1);

	memcpy(nc->proto, proto, sizeof(struct common_protocol));
	memcpy(&nc->unc, unc, sizeof(struct unetchannel));

	memset(&ctl, 0, sizeof(struct unetchannel_control));
	memcpy(&ctl.unc, unc, sizeof(struct unetchannel));

	ctl.cmd = NETCHANNEL_CREATE;
	err = netchannel_control(&ctl);
	if (err < 0 && errno == EEXIST)
		err = 0;
	else if (err > 0) {
		nc->fd = err;
		err = nc->proto->create(nc);
	}
	
	if (err) {
		free(nc);
		nc = NULL;
	}

	netchannel_dump(&ctl.unc, "create", err, 0);
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
	unsigned char buf[4096];
	struct unetchannel_control *ctl = (struct unetchannel_control *)buf;
	struct iphdr *iph = ncb->nh.iph;

	if (ncb->len > sizeof(buf) - sizeof(struct unetchannel_control))
		return -EINVAL;

	memset(buf, 0, sizeof(buf));

	ctl->cmd = NETCHANNEL_SEND;
	ctl->fd = ncb->nc->fd;
	ctl->len = ncb->len;
	ctl->header_len = iph->ihl * 4;
	ctl->timeout = ncb->nc->unc.init_stat_work;

	memcpy(&ctl->unc, &ncb->nc->unc, sizeof(struct unetchannel));

	memcpy(&buf[sizeof(struct unetchannel_control)], ncb->head, ncb->len);

	syscall_send++;

	return netchannel_control(ctl);
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
		unsigned int laddr, unsigned short lport,
		unsigned int faddr, unsigned short fport,
		unsigned int proto, unsigned int state,
		unsigned int timeout, unsigned int order)
{
	unc->memory_limit_order = order;
	unc->faddr = faddr;
	unc->laddr = laddr;
	unc->fport = htons(fport);
	unc->lport = htons(lport);
	unc->proto = proto;
	unc->state = state;
	unc->init_stat_work = timeout;
	unc->copy = NETCHANNEL_COPY_USER;
}
