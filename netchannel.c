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

#include <linux/if_ether.h>

#include "sys.h"

int packet_index = 1;
unsigned char packet_edst[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

#ifdef KERNEL_NETCHANNEL
#include <linux/unistd.h>

int netchannel_recv_raw(struct netchannel *nc, unsigned int tm)
{
	struct nc_buff *ncb;
	int err;
	struct pollfd pfd;

	pfd.fd = nc->fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	syscall_recv += 1;

	err = poll(&pfd, 1, tm);
	if (err < 0) {
		return err;
	}

	if (!(pfd.revents & POLLIN) || !err) {
		ulog("%s: no data.\n", __func__);
		return -EAGAIN;
	}

	syscall_recv += 1;

	ncb = ncb_alloc(4096);
	if (!ncb)
		return -ENOMEM;

	err = read(nc->fd, ncb->head, ncb->len);
	if (err < 0) {
		if (errno == EAGAIN)
			err = -EAGAIN;
		else
			ulog_err("%s: failed to read", __func__);
		goto err_out_free;
	}
	if (err == 0) {
		err = -EAGAIN;
		goto err_out_free;
	}

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

	err = write(nc->fd, ncb->head, ncb->len);
	if (err < 0) {
		ulog_err("Failed to send a packet: len: %u, fd: %d", ncb->len, nc->fd);
		return err;
	}

	syscall_send++;
	return 0;
}

static int netchannel_create_raw(struct netchannel *nc)
{
	return syscall(__NR_netchannel_create, &nc->ctl);
}

#else
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <unistd.h>
#include <fcntl.h>

static void netchannel_prepare_sockaddr(struct sockaddr_ll *sa)
{
	memset(sa, 0, sizeof(struct sockaddr_ll));

	sa->sll_family 	= PF_PACKET;
	sa->sll_protocol = htons(ETH_P_IP);
	sa->sll_halen 	= ETH_ALEN;
	sa->sll_ifindex = packet_index;
	sa->sll_pkttype = PACKET_OUTGOING;

	memcpy(sa->sll_addr, packet_edst, ETH_ALEN);
}

int netchannel_send_raw(struct nc_buff *ncb)
{
	struct netchannel *nc = ncb->nc;
	int err;
	struct sockaddr_ll sa;

	netchannel_prepare_sockaddr(&sa);

	err = sendto(nc->fd, ncb->head, ncb->len, 0, (struct sockaddr *)&sa, sizeof(sa));
	if (err < 0) {
		ulog_err("Failed to send a packet: len: %u, fd: %d", ncb->len, nc->fd);
		return err;
	}

	syscall_send++;
	return 0;
}

int netchannel_recv_raw(struct netchannel *nc, unsigned int tm)
{
	struct nc_buff *ncb;
	int err, received = 0;
	struct pollfd pfd;
	struct sockaddr_ll sa;
	socklen_t len = sizeof(sa);
	
	netchannel_prepare_sockaddr(&sa);

	pfd.fd = nc->fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	syscall_recv += 1;

	err = poll(&pfd, 1, tm);
	if (err < 0) {
		ulog_err("%s: failed to poll", __func__);
		return err;
	}
	if (!(pfd.revents & POLLIN) || !err) {
		ulog("%s: no data, revents: %x.\n", __func__, pfd.revents);
		return -EAGAIN;
	}

	syscall_recv += 1;

	do {
		ncb = ncb_alloc(4096);
		if (!ncb)
			return -ENOMEM;
		ncb->nc = nc;

		err = recvfrom(nc->fd, ncb->head, ncb->len, 0, (struct sockaddr *)&sa, &len);
		if (err < 0) {
			ulog_err("%s: failed to read", __func__);
			err = -errno;
			goto err_out_free;
		}

		ncb_trim(ncb, err);

		err = packet_ip_process(ncb);
		if (err) {
			err = 1;
			ncb_put(ncb);
		}
		++received;
	} while (err > 0 && ++received < 50);

	return 0;

err_out_free:
	ncb_put(ncb);
	return err;
}

static int netchannel_create_raw(struct netchannel *nc)
{
	int s;
	struct sockaddr_ll sa;

	s = socket(PF_PACKET, SOCK_DGRAM, nc->ctl.saddr.proto);
	if (s < 0) {
		ulog_err("Failed to create packet socket");
		return -1;
	}

	netchannel_prepare_sockaddr(&sa);

	if (bind(s, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll))) {
		ulog_err("bind");
		close(s);
		return -1;
	}

	return s;
}

#endif

void netchannel_remove(struct netchannel *nc)
{
	close(nc->fd);
}

struct netchannel *netchannel_create(struct netchannel_control *ctl, unsigned int state)
{
	int err;
	struct common_protocol *proto;
	struct netchannel *nc;

	if (ctl->saddr.proto == IPPROTO_TCP)
		proto = &atcp_common_protocol;
	else if (ctl->saddr.proto == IPPROTO_UDP)
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
	nc->header_size = MAX_HEADER_SIZE;

	memcpy(nc->proto, proto, sizeof(struct common_protocol));
	memcpy(&nc->ctl, ctl, sizeof(struct netchannel_control));

	nc->fd = netchannel_create_raw(nc);
	if (nc->fd < 0) {
		ulog_err("Failed to create netchannel");
		goto err_out_free;
	}

	err = nc->proto->create(nc);
	if (err)
		goto err_out_free;

	return nc;

err_out_free:
	free(nc);
	return NULL;
}

int netchannel_send(struct netchannel *nc, void *buf, unsigned int size)
{
	return nc->proto->process_out(nc, buf, size);
}

int netchannel_recv(struct netchannel *nc, void *buf, unsigned int size)
{
	return nc->proto->process_in(nc, buf, size);
}
