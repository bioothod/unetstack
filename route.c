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

struct nc_route *route_get(__u32 dst, __u32 src)
{
	unsigned int i;
	struct nc_route *rt = NULL;

	for (i=0; i<route_num; ++i) {
		if (dst == route_table[i].dst) {
			rt = &route_table[i];

			if (src == route_table[i].src)
				break;
		}
	}
#if 0
	if (rt)
		ulog("%u.%u.%u.%u -> %u.%u.%u.%u, proto: %u, header_size: %u.\n",
			NIPQUAD(rt->src), NIPQUAD(rt->dst), rt->proto, rt->header_size);
#endif
	return rt;
}

void route_put(struct nc_route *rt)
{
}

int route_init(void)
{
	route_num = 0;
	return 0;
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

	memcpy(&route_table[route_num - 1], rt, sizeof(struct nc_route));

	return 0;
}
