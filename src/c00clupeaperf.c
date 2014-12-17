/**
 *
 * cooclupea Honeypot 
 * <*))><
 *
 * (C) 2014 by Christoph Pohl (c00clupea@googlemail.com)
 * released under the GPLv.2
 * 
 * File:	c00clupeaperf.c
 * created: 	Tue Dec 16 17:24:42 2014
 * author:  	Christoph Pohl <c00clupea@gmail.com>
 */
#include "c00clupeaperf.h"

static inline int __diff_timespecs(struct timespec *r, struct timespec *a, struct timespec *b);
static inline int __call_system(struct c00_measure_conf *config, struct c00_measure_result *result);
static inline int __destroy_all(struct c00_measure_conf *config, struct c00_measure_result *result);
static inline int __calc_sec(struct timespec *t, float *r);


int measure_exvp(struct c00_measure_conf *config, struct c00_measure_result *result){
	echocheck(config,"Sorry you need at least a config %s","struct");
	struct timespec start, stop;

	if( clock_gettime( CLOCK_REALTIME, &start) == -1 ) {
		C00WRITEN("Can not use start clock\n");
		C00DEBUG("Troubles with clock %s"," start");
		return ERROR;
	}
	
	__call_system(config,result);

	if( clock_gettime( CLOCK_REALTIME, &stop) == -1 ) {
		C00WRITEN("Can not use stop clock\n");
		C00DEBUG("Troubles with clock %s","stop");
		return ERROR;
	}

	__diff_timespecs(result->exvptime, &stop, &start);		

	return TRUE;
error:
	return ERROR;
}

int main( int argc, char **argv ){
	int i = 0;
	struct c00_measure_conf *config = malloc(sizeof(struct c00_measure_conf));
	struct c00_measure_result *result = malloc(sizeof(struct c00_measure_result));
	result->exvptime = malloc(sizeof(struct timespec));
#if OSDETECTED == DARWIN
	fprintf(stdout,"You use a system (Darwin) without monothonic counter....you should approximate more measurements\n");
#endif	

	echocheck(argc > 1,"Sorry but you need at least one command you have %d arguments...\n",argc - 1);
	
	memset(config->flags,0,BITNSLOTS(MAX_BITSET));

	for(i = 1; i < argc; i++){
		if(check_argv(i,"--mem","-m")){
			BITSET(config->flags, MEASURE_MEM);
			continue;
		}
		if(check_argv(i,"--time","-t")){
			BITSET(config->flags, MEASURE_TIME);
			continue;
		}
		if(check_argv(i,"--verbose","-v")){
			BITSET(config->flags, MEASURE_VERBOSE);
			continue;
		}
		
		if(i == argc - 1){
			strncpy(config->cmd,argv[i],1024);
		}
	}
	
	echocheck(config->cmd,"Command not existing, usage %s","c00clupeaperf <options> command");
	
	C00DEBUG("Command :%s",config->cmd);

	if(measure_exvp(config,result) != TRUE){
		__destroy_all(config,result);
		goto error;
	}
	if(BITTEST(config->flags, MEASURE_TIME)){
		C00WRITE("Result time %ld sec %ld ns\n",result->exvptime->tv_sec,result->exvptime->tv_nsec);
		float res =  0;
		__calc_sec(result->exvptime, &res);
		C00WRITE("Result time %f sec\n",res);
		
	}
	__destroy_all(config,result);
	return TRUE;
error:
	fprintf(stdout,"Exit with error...see logfiles\n");
	exit(1);
}


static inline int __diff_timespecs(struct timespec *r, struct timespec *a, struct timespec *b){
	r->tv_sec = a->tv_sec - b->tv_sec;
	if (a->tv_nsec < b->tv_nsec) {
		r->tv_nsec = a->tv_nsec + 1000000000L - b->tv_nsec;
		r->tv_sec--;
	} else {
		r->tv_nsec = a->tv_nsec - b->tv_nsec ;
	}
	return TRUE;
}

static inline int __call_system(struct c00_measure_conf *config, struct c00_measure_result *result){
	result->code = system(config->cmd);
	return TRUE;
	
}


static inline int __destroy_all(struct c00_measure_conf *config, struct c00_measure_result *result){
	free(config);
	free(result->exvptime);
	free(result);
	return TRUE;
}

static inline int __calc_sec(struct timespec *t, float *r){
	*r = (float)t->tv_sec + NSTOS(t->tv_nsec);
	return TRUE;
}
