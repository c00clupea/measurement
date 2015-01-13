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
static void *__mem_measure(void *arg);
static inline int __mem_loop(FILE *logf, char *memf);
static inline int __calc_cpu_perf(struct c00_stat *stat, long fiffies, struct c00_stat_rem *oldstat);

static pthread_t mem_thread;
static pthread_t cpu_thread;

int measure_call(struct c00_measure_conf *config, struct c00_measure_result *result){
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
	#if OSDETECTED == LINUX
	if(BITTEST(config->flags, MEASURE_MEM)){
		pthread_join(mem_thread,NULL);
	}
	if(BITTEST(config->flags, MEASURE_CPU)){
		pthread_join(cpu_thread,NULL);
	}
	#endif
	__diff_timespecs(result->exvptime, &stop, &start);		

	return TRUE;
error:
	return ERROR;
}

int init_config(struct c00_measure_conf *config){
	memset(config->flags,0,BITNSLOTS(MAX_BITSET));
	memset(config->ident,'\0',1024);
	memset(config->cmd,'\0',1024);
	memset(config->logpattern,'\0',1024);
	return TRUE;
}

#ifdef PERFMAIN
int main( int argc, char **argv ){
	int i = 0;
	long lmem = 100000;
	long lcpu = 100000;
	struct c00_measure_conf *config = malloc(sizeof(struct c00_measure_conf));
	struct c00_measure_result *result = malloc(sizeof(struct c00_measure_result));
	result->exvptime = malloc(sizeof(struct timespec));




	init_config(config);

	for(i = 1; i < argc; i++){
		if(check_argv(i,"--mem","-m")){
#if OSDETECTED != LINUX
			C00WRITEN("Sorry, memory measurement only with Linux..");
			exit(1);
#endif
			if(i + 1 >= argc - MINARGC){
				C00WRITEN("Sorry but memory neds a resolution in ms -m 100000 for 0.1 sec res");
				exit(1);
			}
			lmem = atol(argv[i+1]);
			if(lmem == 0){
				C00WRITEN("Sorry but memory neds a resolution in ms -m 100000 for 0.1 sec res");
				exit(1);
			}
			

			BITSET(config->flags, MEASURE_MEM);
			i++;
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
		if(check_argv(i,"--cpu","-c")){
#if OSDETECTED != LINUX
			C00WRITEN("Sorry, memory measurement only with Linux..");
			exit(1);
#endif
			if(i + 1 >= argc - MINARGC){
				C00WRITEN("Sorry but cpu needs a resolution in ms -c 100000 for 0.1 sec res");
				exit(1);
			}
			lcpu = atol(argv[i+1]);
			if(lcpu == 0){
				C00WRITEN("Sorry but cpu needs a resolution in ms -c 100000 for 0.1 sec res");
				exit(1);
			}

			BITSET(config->flags, MEASURE_CPU);
			i++;
			continue;
		}
		if(check_argv(i,"--help","-h")){
			C00WRITE("%s\n\n",USAGEPATTERN);
			C00WRITEN("Options:\n--mem     -m Measure memory\n--time    -t Measure time\n--execvp  -e Call with execvp (Default system)\n--verbose -v verbose\n--help    -h does what command means\n");
			exit(0);
		}

		if(i == argc - 3){
			strncpy(config->logpattern,argv[i],1024);
		}

		if(i == argc - 2){
			strncpy(config->ident,argv[i],1024);
		}
		
		if(i == argc - 1){
			strncpy(config->cmd,argv[i],1024);
		}
	}

	echocheck(argc > MINARGC,"Sorry but you need at least %d commands you have %d arguments...\n",MINARGC,argc - 1);

	echocheck(config->ident && config->ident[0] != '\0',"You have to set the id, usage %s \n",USAGEPATTERN);
	echocheck(config->logpattern && config->logpattern[0] != '\0',"You have to set the logpattern, usage %s \n",USAGEPATTERN);
	echochecktrue(!BITTEST(config->flags, MEASURE_EXECVP) && BITTEST(config->flags, MEASURE_MEM),"You can not use system together with memcheck...use execvp (-e) usage: %s",USAGEPATTERN);
	echochecktrue(!BITTEST(config->flags, MEASURE_EXECVP) && BITTEST(config->flags, MEASURE_CPU),"You can not use system together with cpucheck...use execvp (-e) usage: %s",USAGEPATTERN);
	if(__init_logs(config)!= TRUE){
		__destroy_all(config,result);
		goto error;
	}
	

	char time_res[30];
	__time_as_char(LOGDATEFMT,LOGDATEBUF,time_res);

/*This is ugly, but does not waste sourcecode*/
	C00WRITEVERBOSEN("Call c00clupeaperf with options :");
	C00LOG("Measurement at %s options:",time_res);
	IFCONFIGSET(MEASURE_MEM,C00WRITEVERBOSEN("|Measure Memory");C00LOGN("|Measure Memory"););
	IFCONFIGSET(MEASURE_TIME,C00WRITEVERBOSEN("|Measure Time");C00LOGN("|Measure Time"););
	IFCONFIGSET(MEASURE_CPU,C00WRITEVERBOSEN("|Measure CPU");C00LOGN("|Measure CPU"););
	IFCONFIGSET(MEASURE_EXECVP,C00WRITEVERBOSEN("|execvp");C00LOGN("|execvp"););
	IFCONFIGSET(MEASURE_VERBOSE,C00WRITEVERBOSEN("|verbose");C00LOGN("|verbose"););
	C00WRITEVERBOSEN("|\n");
	C00LOGN("|\n");
	
	echocheck(config->cmd && config->cmd[0] != '\0',"You have to set the command, usage %s \n",USAGEPATTERN);

#if OSDETECTED == DARWIN
	fprintf(stdout,"You use a system (Darwin) without monothonic counter....you should approximate more measurements\n");
#endif	
#if OSDETECTED == LINUX
	fprintf(stdout,"You use a system (Linux) with monothonic counter....\n");
#endif	
	
	C00DEBUG("Command :%s",config->cmd);
	char tmpcmd[1024];
	strncpy(tmpcmd,config->cmd,1024);
	__parse_command(tmpcmd,config->argv);
	config->resolution = lmem;
	config->cresolution = lcpu;
	if(measure_call(config,result) != TRUE){
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

#endif

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

static inline int __stat_loop(FILE *logf, char *statf,struct c00_stat_rem *oldstat){
	const char *format = "%d %s %c %d %d %d %d %d %lu %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %lu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %lu %lu %llu";
	FILE *f;
	f = fopen(statf,"r");
	if(!f){
		return FALSE;
	}

	FILE *fp;
	fp = fopen("/proc/stat","r");
	if(!fp){
		return FALSE;
	}

	char ccpu[4];
	char clcpu[256];

	const char *formatstat = "%s %s";
	long fiffies = 0;
	if(2 == fscanf(fp, formatstat,ccpu,clcpu)){
		char *ptr;
		char delimit[] = " ";
		ptr = strtok(clcpu,delimit);

		while(ptr != NULL){
			fiffies += atol(ptr);
			ptr = strtok(NULL,delimit);
		}
	}

	struct c00_stat *s;
	s = malloc(sizeof(struct c00_stat));
	if (42==fscanf(f, format, 
	    &s->pid,
	    s->comm,
	    &s->state,
	    &s->ppid,
	    &s->pgrp,
	    &s->session,
	    &s->tty_nr,
	    &s->tpgid,
	    &s->flags,
	    &s->minflt,
	    &s->cminflt,
	    &s->majflt,
	    &s->cmajflt,
	    &s->utime,
	    &s->stime,
	    &s->cutime,
	    &s->cstime,
	    &s->priority,
	    &s->nice,
	    &s->num_threads,
	    &s->itrealvalue,
	    &s->starttime,
	    &s->vsize,
	    &s->rss,
	    &s->rlim,
	    &s->startcode,
	    &s->endcode,
	    &s->startstack,
	    &s->kstkesp,
	    &s->kstkeip,
	    &s->signal,
	    &s->blocked,
	    &s->sigignore,
	    &s->sigcatch,
	    &s->wchan,
	    &s->nswap,
	    &s->cnswap,
	    &s->exit_signal,
	    &s->processor,
	    &s->rt_priority,
	    &s->policy,
	    &s->delayacct_blkio_ticks
		)){
		fclose(f);
		fclose(fp);
		fprintf(stderr,"pid %d\n",s->pid);
		if(oldstat->init != TRUE){
	__calc_cpu_perf(s,fiffies,oldstat);
			
		}
		oldstat->init = FALSE;
		oldstat->utime = s->utime;
		oldstat->stime = s->stime;
		oldstat->cutime = s->cutime;
		oldstat->cstime = s->cstime;
		oldstat->uptime = fiffies;
		free(s);
		return TRUE;
	}else{
		/**last one**/
		
		fclose(f);
		fclose(fp);
		free(s);
		return FALSE;
	}
}

static inline int __calc_cpu_perf(struct c00_stat *s, long fiffies, struct c00_stat_rem *oldstat){
	long rutime = s->utime - oldstat->utime;
	long rstime = s->stime - oldstat->stime;
	long rcutime = s->cutime - oldstat->cutime;
	long rcstime = s->cstime - oldstat->cstime;
	long ruptime = fiffies - oldstat->uptime;
	fprintf(stderr,"rupt: %lu, rut: %lu, rst: %lu, rcu: %lu, rcs: %lu",ruptime,rutime,rstime,rcutime,rcstime);
}

/**borrowed from http://locklessinc.com/downloads/tmem.c**/
static inline int __mem_loop(FILE *logf, char *memf){
	char *line;
	char *vmsize;
	char *vmpeak;
	char *vmrss;
	char *vmhwm;

	size_t len;
	FILE *f;

	vmsize = NULL;
	vmpeak = NULL;
	vmrss = NULL;
	vmhwm = NULL;
	line = malloc(128);
	len = 128;
	f = fopen(memf,"r");

	if(!f){
		return FALSE;
	}

	while(!vmsize || !vmpeak || !vmrss || !vmhwm){
		if(getline(&line, &len, f) == -1){
			return FALSE;
		}
		/* Find VmPeak */
		if (!strncmp(line, "VmPeak:", 7))
		{
			vmpeak = strdup(&line[7]);
		}
		
		/* Find VmSize */
		else if (!strncmp(line, "VmSize:", 7))
		{
			vmsize = strdup(&line[7]);
		}
		
		/* Find VmRSS */
		else if (!strncmp(line, "VmRSS:", 6))
		{
			vmrss = strdup(&line[7]);
		}
		
		/* Find VmHWM */
		else if (!strncmp(line, "VmHWM:", 6))
		{
			vmhwm = strdup(&line[7]);
		}
	}
	free(line);
	fclose(f);
	/* Get rid of " kB\n"*/
	len = strlen(vmsize);
	vmsize[len - 4] = 0;
	len = strlen(vmpeak);
	vmpeak[len - 4] = 0;
	len = strlen(vmrss);
	vmrss[len - 4] = 0;
	len = strlen(vmhwm);
	vmhwm[len - 4] = 0;

	fprintf(stderr, "%s\t%s\t%s\t%s\n", vmsize, vmpeak, vmrss, vmhwm);

	free(vmpeak);
	free(vmsize);
	free(vmrss);
	free(vmhwm);

	return TRUE;
}

static void *__cpu_measure(void *arg){
	struct c00_measure_conf *config = (struct c00_measure_conf*)arg;
	struct c00_stat_rem *stat_rem = malloc(sizeof(struct c00_stat_rem));
	char buf[PATH_MAX];

	snprintf(buf, PATH_MAX, "/proc/%d/stat",config->pid);
	FILE *f;
	f = fopen("cputest","w");
	stat_rem->utime = 0;
	stat_rem->stime = 0;
	stat_rem->cutime = 0;
	stat_rem->cstime = 0;
	stat_rem->uptime = 0;
	stat_rem->init = TRUE;

	while(__stat_loop(f,buf,stat_rem) == TRUE){
		usleep(config->cresolution);
	}
	fclose(f);
	return NULL;
}

static void *__mem_measure(void *arg){

	struct c00_measure_conf *config = (struct c00_measure_conf*)arg;
	
//	C00WRITEN("Measure mem");

	char buf[PATH_MAX];
	
	snprintf(buf, PATH_MAX, "/proc/%d/status", config->pid);
	FILE *f;
	f = fopen("test","w");
	
	while(__mem_loop(f,buf) == TRUE){

		usleep(config->resolution);

	}
	fclose(f);
	return NULL;
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
		config->pid = pid;
		
		#if OSDETECTED == LINUX
		if(BITTEST(config->flags, MEASURE_MEM)){	
			
			int rc;
			rc = pthread_create(&mem_thread, NULL, &__mem_measure,config);
		}
		if(BITTEST(config->flags, MEASURE_CPU)){	
			
			int rcc;
			rcc = pthread_create(&cpu_thread, NULL, &__cpu_measure,config);
		}
		#endif
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
	char finame[PATH_MAX];
	sprintf(finame,config->logpattern,config->ident,"desc");
	config->logfp = fopen(finame,"w");
	if(!config->logfp){
		C00WRITE("Unable to open %s for write access\n",finame);
		return ERROR;
	}
	return TRUE;
}

