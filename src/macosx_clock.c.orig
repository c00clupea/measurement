/**
 *
 * cooclupea Honeypot 
 * <*))><
 *
 * (C) 2014 by Christoph Pohl (c00clupea@googlemail.com)
 * released under the GPLv.2
 * 
 * File:	macosx_clock.c
 * created: 	Wed Dec 17 12:37:35 2014
 * author:  	Christoph Pohl <c00clupea@gmail.com>
 */
#include "macosx_clock.h"

/**
 *The unused attribute is here to avoid dependencies to the global.h So no macro here
 */

int clock_gettime(__attribute__((unused)) int clk_id, struct timespec* t) {
    struct timeval now;
    if(gettimeofday(&now, NULL) != 0){
	    return -1;
    }
    t->tv_sec  = now.tv_sec;
    t->tv_nsec = now.tv_usec * 1000;
    return 0;
}
