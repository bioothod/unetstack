/*
 * 	route.c
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

#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "sys.h"

static unsigned int route_num = 0;
static struct nc_route *route_table;

int route_get(__u32 dst, __u32 src, struct nc_route *rt)
{
	unsigned int i;
	int err = -ENODEV;

	for (i=0; i<route_num; ++i) {
		if (dst == route_table[i].dst) {
			err = 0;
			rt->src = route_table[i].src;
			rt->dst = route_table[i].dst;
			memcpy(rt->edst, route_table[i].edst, ETH_ALEN);
			memcpy(rt->esrc, route_table[i].esrc, ETH_ALEN);

			if (src == route_table[i].src)
				break;
		}
	}

	return err;
}

int route_init(void)
{
	struct nc_route rt;
	__u8 edst[] = {0x00, 0x00, 0x21, 0x01, 0x95, 0xD1};
	__u8 esrc[] = {0x00, 0x08, 0x02, 0xE4, 0x40, 0xF2};
	
	rt.src = num2ip(10,0,0,5);
	rt.dst = num2ip(10,0,0,1);
	memcpy(rt.edst, edst, ETH_ALEN);
	memcpy(rt.esrc, esrc, ETH_ALEN);

	return route_add(&rt);
}

void route_fini(void)
{
	route_num = 0;
	free(route_table);
}

int route_add(struct nc_route *rt)
{
	unsigned int i;

	for (i=0; i<route_num; ++i)
		if (rt->dst == route_table[i].dst && rt->src == route_table[i].src)
			return 0;

	route_num++;
	route_table = realloc(route_table, sizeof(struct nc_route) * route_num);
	if (!route_table)
		return -ENOMEM;
			
	route_table[route_num - 1].src = rt->src;
	route_table[route_num - 1].dst = rt->dst;
	memcpy(route_table[route_num - 1].esrc, rt->esrc, ETH_ALEN);
	memcpy(route_table[route_num - 1].edst, rt->edst, ETH_ALEN);

	return 0;
}
