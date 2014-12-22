AM_CFLAGS =  -std=gnu99 -Wall -Wextra -pedantic -D_THREAD_SAFE

if NEEDPTHREAD
AM_CFLAGS += -pthread
endif

if CLANG
AM_CFLAGS += -Wno-extended-offsetof
endif

AM_CPPFLAGS = 

bin_PROGRAMS =

if PERFMAIN
bin_PROGRAMS += c00clupeaperf
endif

if PERFMAIN
c00clupeaperf_SOURCES = c00clupeaperf.h c00clupeaperf.c
endif


if ISDARWIN
if PERFMAIN
c00clupeaperf_SOURCES += macosx_clock.h macosx_clock.c
endif
endif
