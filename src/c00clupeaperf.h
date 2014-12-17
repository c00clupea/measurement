/**
 *
 * cooclupea Honeypot 
 * <*))><
 *
 * (C) 2014 by Christoph Pohl (c00clupea@googlemail.com)
 * released under the GPLv.2
 * 
 * File:	c00clupeaperf.h
 * created: 	Tue Dec 16 17:24:25 2014
 * author:  	Christoph Pohl <c00clupea@gmail.com>
 */
#ifndef _C00CLUPEAPERF_H_
#define _C00CLUPEAPERF_H_
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <limits.h>		/* for CHAR_BIT */
#include "global.h"

#if OSDETECTED == DARWIN
#include "macosx_clock.h" 
#endif

#define BITMASK(b) (1 << ((b) % CHAR_BIT))
#define BITSLOT(b) ((b) / CHAR_BIT)
#define BITSET(a, b) ((a)[BITSLOT(b)] |= BITMASK(b))
#define BITCLEAR(a, b) ((a)[BITSLOT(b)] &= ~BITMASK(b))
#define BITTEST(a, b) ((a)[BITSLOT(b)] & BITMASK(b))
#define BITNSLOTS(nb) ((nb + CHAR_BIT - 1) / CHAR_BIT)

#define BILLION  1000000000L;



#define MAX_BITSET 3

#define MEASURE_TIME 1
#define MEASURE_MEM 2
#define MEASURE_VERBOSE 3

#define C00WRITEVERBOSE(fmt,...)		\
	if(BITTEST(config->flags, MEASURE_VERBOSE)){	\
		fprintf(stdout,fmt,__VA_ARGS__);	\
	}		

#define C00WRITEVERBOSEN(fmt)		\
	if(BITTEST(config->flags, MEASURE_VERBOSE)){	\
		fprintf(stdout,fmt);	\
	}

#define C00WRITEN(fmt)		\
		fprintf(stdout,fmt)	\


#define C00WRITE(fmt,...)					\
	fprintf(stdout,fmt,__VA_ARGS__)					\
	


struct c00_measure_conf{
	char flags[BITNSLOTS(MAX_BITSET)];
	char cmd[1024];
};

struct c00_measure_result{
	struct timespec *exvptime;
};

int measure_exvp(struct c00_measure_conf *config,struct c00_measure_result *result);

int main( int argc, char **argv );


#endif /* _C00CLUPEAPERF_H_ */
