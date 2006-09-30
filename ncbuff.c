/*
 * 	ncbuff.h
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

#include "sys.h"

struct nc_buff *ncb_alloc(unsigned int size)
{
	struct nc_buff *ncb;

	ncb = malloc(sizeof(struct nc_buff));
	if (!ncb)
		return NULL;

	memset(ncb, 0, sizeof(struct nc_buff));

	ncb->len = ncb->total_size = size;

	ncb->data = ncb->head = malloc(size);
	if (!ncb->data) {
		free(ncb);
		return NULL;
	}
	memset(ncb->data, 0, ncb->total_size);

	ncb_timestamp(ncb);
	ncb->refcnt = 1;
	ncb->tail = ncb->end = ncb->head + ncb->len;

	return ncb;
}

void ncb_free(struct nc_buff *ncb)
{
	memset(ncb->data, 0xFF, ncb->total_size);
	free(ncb->data);
	memset(ncb, 0xFF, sizeof(struct nc_buff));
	free(ncb);
}
