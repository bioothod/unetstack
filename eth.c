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

int eth_build_header(struct nc_buff *ncb)
{
	struct ether_header *eth;

	eth = ncb_push(ncb, sizeof(struct ether_header));
	if (!eth)
		return -ENOMEM;

	memcpy(eth->ether_dhost, ncb->dst->edst, ETH_ALEN);
	memcpy(eth->ether_shost, ncb->dst->esrc, ETH_ALEN);
	eth->ether_type = htons(ETH_P_IP);
	return 0;
}

int packet_eth_process(struct netchannel *nc)
{
	struct nc_buff *ncb;
	struct ether_header *eth;
	int err;

	ncb = ncb_alloc(4096);
	if (!ncb)
		return -ENOMEM;

	err = read(nc->fd, ncb->head, ncb->len);
	if (err < 0) {
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
