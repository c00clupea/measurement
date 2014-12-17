/**
 *
 * cooclupea Honeypot 
 * <*))><
 *
 * (C) 2014 by Christoph Pohl (c00clupea@googlemail.com)
 * released under the GPLv.2
 * 
 * File:	global.h
 * created: 	Wed Dec 17 15:58:52 2014
 * author:  	Christoph Pohl <c00clupea@gmail.com>
 */
#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#include "conf.h"



#define UNUSED __attribute__((unused))

#define FALSE 0
#define ERROR -1
#define TRUE 1

#ifdef WRITEC00CRAP

#define C00DEBUG(fmt,...)\
	fprintf(stdout,"%s:%d ",__FILE__,__LINE__);\
	fprintf(stdout,fmt,__VA_ARGS__);\
	fprintf(stdout,"\n")

#define C00REACH(id)					\
	fprintf(stdout,"reach: %d --> %s:%d\n",id,__FILE__,__LINE__)

#define C00RKILL()\
	fprintf(stdout,"reached kill code");exit(1)

#define C00FKILL(fmt,...)\
	fprintf(stdout,"%s:%d ",__FILE__,__LINE__);\
	fprintf(stdout,fmt,__VA_ARGS__);\
	fprintf(stdout,"\n");\
	exit(1)


#else
#define C00DEBUG(fmt,...)
#define C00REACH(id)
#define C00RKILL()
#define C00FKILL(fmt,...)

#endif


#define check_argv(M,N,O)		\
	(strcmp(argv[M],N) == 0) || (strcmp(argv[M],O) == 0)	\

//Some ideas from http://c.learncodethehardway.org/book/ex20.html
#define check(A, M, ...) if(!(A)) { C00DEBUG(M, __VA_ARGS__); syslog(LOG_ERR,M,__VA_ARGS__);goto error; }

#define echocheck(A,M,...)if(!(A)) { C00DEBUG(M, __VA_ARGS__); fprintf(stderr,M,__VA_ARGS__);goto error; }

#define echoerror(M,...) C00DEBUG(M, __VA_ARGS__); fprintf(stderr,M,__VA_ARGS__);goto error; 

#define mem_check(A) check((A), "%d Out of memory.",-1)

#endif /* _GLOBAL_H_ */
