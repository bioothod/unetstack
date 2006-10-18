/*
 * 	eth.c
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
#include <sys/socket.h>
#include <sys/poll.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include "sys.h"

int packet_eth_process(struct netchannel *nc, unsigned int tm)
{
	struct nc_buff *ncb;
	struct ether_header *eth;
	int err;
	struct pollfd pfd;

	ncb = ncb_alloc(4096);
	if (!ncb)
		return -ENOMEM;

	pfd.fd = nc->fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	err = poll(&pfd, 1, tm);
	if (err < 0) {
		ulog_err("%s: failed to read", __func__);
		return err;
	}

	if (!(pfd.revents & POLLIN) || !err) {
		ulog("%s: no data.\n", __func__);
		return -EAGAIN;
	}

	err = read(nc->fd, ncb->head, ncb->len);
	if (err < 0) {
		ulog_err("%s: failed to read", __func__);
		return err;
	}
	if (err == 0)
		return -EAGAIN;

	ncb_trim(ncb, err);
#if 0
	eth = ncb_pull(ncb, sizeof(struct ether_header));
	if (!eth)
		goto err_out_free;

	ulog("%s: %02x.%02x.%02x.%02x.%02x.%02x -> %02x.%02x.%02x.%02x.%02x.%02x, proto: %04x.\n",
			__func__,
			eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5], 
			eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5], 
			ntohs(eth->ether_type));

	if (ntohs(eth->ether_type) != ETH_P_IP) {
		err = -1;
		goto err_out_free;
	}
#endif
	ncb->nc = nc;

	err = packet_ip_process(ncb);
	if (err)
		goto err_out_free;

	return 0;

err_out_free:
	ncb_put(ncb);
	return err;
}
