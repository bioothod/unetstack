/*
 * 	udp.c
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

#include "sys.h"

static int udp_connect(struct common_protocol *proto __attribute__ ((unused)),
		struct netchannel *nc __attribute__ ((unused)))
{
	return 0;
}

static int udp_process_in(struct common_protocol *proto __attribute__ ((unused)),
		struct nc_buff *ncb __attribute__ ((unused)),
		unsigned int size)
{
	return size;
}

static int udp_process_out(struct common_protocol *proto __attribute__ ((unused)),
		struct nc_buff *ncb __attribute__ ((unused)),
		unsigned int size)
{
	return size;
}

static int udp_destroy(struct common_protocol *proto __attribute__ ((unused)),
		struct netchannel *nc __attribute__ ((unused)))
{
	return 0;
}

struct udp_protocol
{
	struct common_protocol		cproto;
};

struct common_protocol udp_protocol = {
	.size		= sizeof(struct udp_protocol),
	.connect	= &udp_connect,
	.process_in	= &udp_process_in,
	.process_out	= &udp_process_out,
	.destroy	= &udp_destroy,
};
