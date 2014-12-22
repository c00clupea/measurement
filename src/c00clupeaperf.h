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
#include <stdarg.h>
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

#define NSTOS(N)  (((float)N / 1000000000L));



#define MAX_BITSET 4

#define MEASURE_TIME 1
#define MEASURE_MEM 2
#define MEASURE_VERBOSE 3
#define MEASURE_EXECVP 4
#define LOGDATEFMT "%Y%m%d%H%M"
#define LOGDATEBUF 13 /*12 +1 (\0)*/

#define MINARGC 3

#define USAGEPATTERN "c00clupeaperf <options> logfilefmt ident command"

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

#define C00LOG(fmt,...)			\
	fprintf(config->logfp,fmt,__VA_ARGS__)	\

#define C00LOGN(fmt)			\
	fprintf(config->logfp,fmt)	\

#define IFCONFIGSET(N,D)		\
	if(BITTEST(config->flags, N)){	\
		D			\
	}


struct c00_measure_conf{
	char flags[BITNSLOTS(MAX_BITSET)];
	char cmd[1024];
	char ident[1024];
	char logpattern[1024];
	char *argv[64];
	FILE *logfp;
	
};

struct c00_measure_result{
	struct timespec *exvptime;
	int code;
};

int measure_exvp(struct c00_measure_conf *config,struct c00_measure_result *result);
int init_config(struct c00_measure_conf *config);

#ifdef PERFMAIN
int main( int argc, char **argv );
#endif

#endif /* _C00CLUPEAPERF_H_ */
