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
#include <pthread.h>
#include "global.h"
#include <sys/wait.h>


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



#define MAX_BITSET 7

#define MEASURE_TIME 1
#define MEASURE_MEM 2
#define MEASURE_VERBOSE 3
#define MEASURE_EXECVP 4
#define MEASURE_CPU 5
#define HASAPPEND 6
#define NEWLOG 7
#define LOGDATEFMT "%Y%m%d%H%M"
#define LOGDATEBUF 13 /*12 +1 (\0)*/
#define LOGLINELEN 1024
#define MAXCPUCOLPERCPU 10


#define MINARGC 3

#define USAGEPATTERN "c00clupeaperf <options> logfilefmt ident command\np.ex c00clupeaperf -m 100000 -t -a \"100,200\" \"wert1,wert2\" -e \"mylog_id_%s_type_%s.log\" \"sampleid\" \"uname -mrns\""

#define C00WRITEVERBOSE(fmt,...)		\
    if(BITTEST(config->flags, MEASURE_VERBOSE)){	\
	fprintf(stdout,fmt,__VA_ARGS__);		\
    }

#define C00WRITEVERBOSEN(fmt)		\
    if(BITTEST(config->flags, MEASURE_VERBOSE)){	\
	fprintf(stdout,fmt);				\
    }

#define C00WRITEN(fmt)		\
		fprintf(stdout,fmt)	\


#define C00WRITE(fmt,...)					\
	fprintf(stdout,fmt,__VA_ARGS__)					\

#define C00LOG(fmt,...)			\
	fprintf(stderr,fmt,__VA_ARGS__)	\

#define C00LOGN(fmt)			\
	fprintf(stderr,fmt)	\

#define IFCONFIGSET(N,D)		\
	if(BITTEST(config->flags, N)){	\
		D			\
	}


struct c00_measure_conf {
    char flags[BITNSLOTS(MAX_BITSET)];
    char cmd[1024];
    char ident[1024];
    char logpattern[1024];
    char *argv[64];
    FILE *logfp;
    FILE *statfp;
    FILE *allstatfp;
    FILE *memfp;
    int pid;
    long resolution;
    long cresolution;
    char appendst[1024];
    char appendhead[1024];

};

struct c00_stat_rem {
    long utime;
    long stime;
    long cutime;
    long cstime;
    long uptime;
    char init;
};

struct c00_measure_result {
    struct timespec *exvptime;
    int code;
};

/**borrowed from shttp://www.cs.tufts.edu/comp/111/assignments/a3/proc.c**/

struct c00_stat {
    int pid;			// %d
    char comm[256];		// %s
    char state;			// %c
    int ppid;			// %d
    int pgrp;			// %d
    int session;		// %d
    int tty_nr;			// %d
    int tpgid;			// %d
    unsigned long flags;	// %lu
    unsigned long minflt;	// %lu
    unsigned long cminflt;	// %lu
    unsigned long majflt;	// %lu
    unsigned long cmajflt;	// %lu
    unsigned long utime;	// %lu
    unsigned long stime; 	// %lu
    long cutime;		// %ld
    long cstime;		// %ld
    long priority;		// %ld
    long nice;			// %ld
    long num_threads;		// %ld
    long itrealvalue;		// %ld
    unsigned long starttime;	// %lu
    unsigned long vsize;	// %lu
    long rss;			// %ld
    unsigned long rlim;		// %lu
    unsigned long startcode;	// %lu
    unsigned long endcode;	// %lu
    unsigned long startstack;	// %lu
    unsigned long kstkesp;	// %lu
    unsigned long kstkeip;	// %lu
    unsigned long signal;	// %lu
    unsigned long blocked;	// %lu
    unsigned long sigignore;	// %lu
    unsigned long sigcatch;	// %lu
    unsigned long wchan;	// %lu
    unsigned long nswap;	// %lu
    unsigned long cnswap;	// %lu
    int exit_signal;		// %d
    int processor;		// %d
    unsigned long rt_priority;	// %lu
    unsigned long policy;	// %lu
    unsigned long long delayacct_blkio_ticks;	// %llu
} ;

int measure_call(struct c00_measure_conf *config, struct c00_measure_result *result);
int init_config(struct c00_measure_conf *config);

#ifdef PERFMAIN
int main( int argc, char **argv );
#endif

#endif /* _C00CLUPEAPERF_H_ */
