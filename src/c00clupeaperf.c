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
static inline int __parse_command(char *tmpcmd, char **tmpargv);
static inline int __call_execvp(struct c00_measure_conf *config, struct c00_measure_result *result);
/*static inline int __write_log(struct c00_measure_conf *config, char *fmt,...);*/
static inline int __time_as_char(char *fmt, int buffer, char *result);
static inline int __init_logs(struct c00_measure_conf *config);

int measure_exvp(struct c00_measure_conf *config, struct c00_measure_result *result){
	echocheck(config,"Sorry you need at least a config %s","struct");
	struct timespec start, stop;

	if( clock_gettime( CLOCK_REALTIME, &start) == -1 ) {
		C00WRITEN("Can not use start clock\n");
		C00DEBUG("Troubles with clock %s"," start");
		return ERROR;
	}
	if(BITTEST(config->flags, MEASURE_EXECVP)){
		__call_execvp(config,result);
	}
	else{
		__call_system(config,result);
	}

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
		if(check_argv(i,"--execvp","-e")){
			BITSET(config->flags, MEASURE_EXECVP);
			continue;
		}
		if(check_argv(i,"--help","-h")){
			C00WRITEN("usage: c00clupeaperf [-mtveh] \"COMMAND\"\n");
			C00WRITEN("Options:\n--mem     -m Measure memory\n--time    -t Measure time\n--execvp  -e Call with execvp (Default system)\n--verbose -v verbose\n--help    -h does what command means\n");
			exit(0);
		}
		
		if(i == argc - 1){
			strncpy(config->cmd,argv[i],1024);
		}
	}

	if(__init_logs(config)!= TRUE){
		__destroy_all(config,result);
		goto error;
	}
	

	

/*This is ugly, but does not waste sourcecode*/
	C00WRITEVERBOSEN("Call c00clupeaperf with options :");
	IFCONFIGSET(MEASURE_MEM,C00WRITEVERBOSEN("|Measure Memory"););
	IFCONFIGSET(MEASURE_TIME,C00WRITEVERBOSEN("|Measure Time"););
	IFCONFIGSET(MEASURE_EXECVP,C00WRITEVERBOSEN("|execvp"););
	IFCONFIGSET(MEASURE_VERBOSE,C00WRITEVERBOSEN("|verbose"););
	C00WRITEVERBOSEN("|\n");
	
	echocheck(config->cmd,"Command not existing, usage %s","c00clupeaperf <options> command");

#if OSDETECTED == DARWIN
	fprintf(stdout,"You use a system (Darwin) without monothonic counter....you should approximate more measurements\n");
#endif	
	
	C00DEBUG("Command :%s",config->cmd);
	char tmpcmd[1024];
	strncpy(tmpcmd,config->cmd,1024);
	__parse_command(tmpcmd,config->argv);

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

static inline int __call_execvp(struct c00_measure_conf *config, struct c00_measure_result UNUSED(*result)){
	pid_t pid;
	int status;

	if((pid = fork()) < 0){
		C00WRITEN("Unable to fork");
		return ERROR;
	}
	else if(pid == 0){
		if(execvp(*config->argv,config->argv) < 0){
			C00WRITE("Unable to execute command %s", config->cmd);
			return ERROR;
		}
	}
	else {
		while(wait(&status) != pid){}
	}
	return TRUE;
}


static inline int __destroy_all(struct c00_measure_conf *config, struct c00_measure_result *result){
	if(config->logfp){
	        fclose(config->logfp);
        }
	free(config);
	free(result->exvptime);
	free(result);
	return TRUE;
}

static inline int __calc_sec(struct timespec *t, float *r){
	*r = (float)t->tv_sec + NSTOS(t->tv_nsec);
	return TRUE;
}

static inline int __parse_command(char *tmpcmd, char **tmpargv){
	while(*tmpcmd != '\0'){
		while(*tmpcmd == ' ' || *tmpcmd == '\t' || *tmpcmd == '\n'){
			*tmpcmd++ = '\0';
		}
		*tmpargv++ = tmpcmd;
		while(*tmpcmd != '\0' && *tmpcmd != ' ' && *tmpcmd != '\t' && *tmpcmd != '\n'){
			tmpcmd++;
		}

	}
	*tmpargv = '\0';
	return TRUE;
}

/*static inline int __write_log(struct c00_measure_conf *config, char *fmt,...){
	va_list args;
	va_start(args,fmt);
	fprintf(config->logfp,fmt,args);
	va_end(args);
	return TRUE;
	}*/

static inline int __time_as_char(char *fmt, int buffer, char *result){
	time_t rawtime;
	struct tm *info;
	time( &rawtime );

	info = localtime( &rawtime );
	strftime(result,buffer,fmt, info);
	return TRUE;
}

static inline int __init_logs(struct c00_measure_conf *config){
	char time_res[30];
	__time_as_char(LOGDATEFMT,LOGDATEBUF,time_res);
	char finame[PATH_MAX];
	sprintf(finame,"%s_desc.log",time_res);
	config->logfp = fopen(finame,"w");
	if(!config->logfp){
		C00WRITE("Unable to open %s for write access\n",finame);
		return ERROR;
	}
	return TRUE;
}

