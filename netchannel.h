/*
 * 	netchannel.h
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

#ifndef __NETCHANNEL_H
#define __NETCHANNEL_H

#define NETCHANNEL_ADDR_SIZE		16

struct netchannel_addr
{
	unsigned char			proto;
	unsigned char			size;
	unsigned short			port;
	unsigned char			addr[NETCHANNEL_ADDR_SIZE];
};

/*
 * Destination and source addresses/ports are from receiving point ov view, 
 * i.e. when packet is being received, destination is local address.
 */

struct netchannel_control
{
	struct netchannel_addr		saddr, daddr;
	unsigned int			packet_limit;
};

#endif /* __NETCHANNEL_H */
