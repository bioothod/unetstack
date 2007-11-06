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

#include <linux/types.h>

enum netchannel_commands {
	NETCHANNEL_CREATE = 0,
};

enum netchannel_type {
	NETCHANNEL_EMPTY = 0,
	NETCHANNEL_COPY_USER,
	NETCHANNEL_NAT,
	NETCHANNEL_MAX
};

/*
 * Destination and source addresses/ports are from receiving point ov view, 
 * i.e. when packet is being received, destination is local address.
 */

struct unetdata
{
	__u32			saddr, daddr;
	__u16			sport, dport;
	__u8			proto;			/* IP protocol number */
	__u8			reserved[3];
};

struct unetchannel
{
	struct unetdata		data, mask;
	__u32			prio;			/* Netchanenl's priority. */
	__u32			type;			/* Netchannel type: copy_to_user, NAT or something */
	__u8			memory_limit_order;	/* Memor limit order */
	__u8			reserved[3];
};

struct unetchannel_control
{
	struct unetchannel	unc;
	__u32			cmd;
	__u16			len, header_len;
	__u32			flags;
	__u32			timeout;
	int			fd;
};

#define NETCHANNEL_NAT_CREATE	0x0
#define NETCHANNEL_NAT_REMOVE	0x1

struct netchannel_nat
{
	__u32			cmd;
	struct unetchannel	flow;
	struct unetdata		target;
};

#endif /* __NETCHANNEL_H */
