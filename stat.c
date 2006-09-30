/*
 * 	stat.c
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
#include <sys/types.h>
#include <sys/time.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "stat.h"

#ifdef DEBUG
#define ulog(f, a...) fprintf(stderr, f, ##a)
#else
#define ulog(f, a...)
#endif

#define ulog_err(f, a...) ulog(f ": %s [%d].\n", ##a, strerror(errno), errno)

unsigned long long stat_written = 0, stat_written_msg = 0;
static struct timeval tm1, tm2;
static unsigned long init_utime, init_stime;
int last_fd;

static int cpu_test_usage(unsigned long *sys_utime, unsigned long *sys_stime)
{
	FILE *f;
	char path[64];
	char *ptr, data[256], status;
	char fmt[] = " %c %d %d %d %d %d %lu %lu %lu %lu %lu %lu %lu ";
	int num, good_num = 13, err;
	int ppid, pgrp, session, tty, tpgid;
	unsigned long flags, minflt, cminflt, majflt, cmajflt, utime, stime;
	
	snprintf(path, sizeof(path), "/proc/%d/stat", getpid());
	
	f = fopen(path, "r");
	if (!f) {
		ulog_err("Failed to open %s", path);
		return 1;
	}

	err = -EINVAL;
	ptr = fgets(data, sizeof(data), f);
	if (!ptr) {
		ulog_err("Failed to read data");
		goto err_out_close;
	}
	
	fclose(f);

	data[sizeof(data) - 1] = '\0';
	
	ptr = strrchr(data, ')');
	if (!ptr) {
		ulog("String '%s' is broken.\n", data);
		goto err_out_exit;
	}
	ptr++;
	if (!ptr || !*ptr) {
		ulog("String '%s' is broken.\n", data);
		goto err_out_exit;
	}

	num = sscanf(ptr, fmt, &status, &ppid, &pgrp, 
				&session, &tty, &tpgid, &flags, 
				&minflt, &cminflt, &majflt, &cmajflt, 
				&utime, &stime);

	if (num != good_num) {
		ulog("String '%s' is broken, num=%d, good_num=%d.\n", ptr, num, good_num);
		goto err_out_exit;
	}

	*sys_utime = utime;
	*sys_stime = stime;

	return 0;

err_out_close:
	fclose(f);
err_out_exit:
	return -1;
}

void init_stat(void)
{
	gettimeofday(&tm1, NULL);
	print_stat();
}

void print_stat(void)
{
	unsigned long stime, utime;
	long diff, mdiff;
	double speed, speed_msg;

	stime = utime = 0;

	gettimeofday(&tm2, NULL);
	diff = (tm2.tv_sec - tm1.tv_sec)*1000000 + tm2.tv_usec - tm1.tv_usec;
	mdiff = diff/1000;

	if (!diff || !mdiff)
		return;
	speed = ((double)stat_written)*1000000.0/((double)diff*1024.0*1024.0);
	speed_msg = ((double)stat_written_msg)*1000000.0/((double)diff);

	cpu_test_usage(&utime, &stime);

	utime -= init_utime;
	stime -= init_stime;

	/*
	 * USER_HZ is 100 tics/jiffies per second.
	 *
	 * ?time * 1000 / 100 is ?time in msecs.
	 */

	utime = utime*1000/mdiff;
	stime = stime*1000/mdiff;

	printf("Written %llu Mb, %llu messages, time %f sec, speed %f Mb/sec, %f msg/sec, CPU test_usage user: %3lu, kernel: %3lu, last_fd: %d.\n", 
			stat_written/1024/1024, stat_written_msg, ((double)diff)/1000000.0, speed, speed_msg, utime, stime, last_fd);
	
	init_utime = utime;
	init_stime = stime;
}
