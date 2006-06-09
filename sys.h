/*
 * 	sys.h
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

#ifndef __SYS_H
#define __SYS_H

#include <stdio.h>

typedef unsigned char __u8;

#define PACKET_NAME	"packet"

#ifdef DEBUG
#define uloga(f, a...) fprintf(stderr, f, ##a)
#else
#define uloga(f, a...)
#endif
#define ulog(f, a...) uloga(f, ##a)
#define ulog_err(f, a...) ulog(f ": %s [%d].\n", ##a, strerror(errno), errno)

struct nc_buff
{
	__u8			*data;
	unsigned int		size;
};

extern int packet_ip_send(struct nc_buff *ncb);

#endif /* __SYS_H */
