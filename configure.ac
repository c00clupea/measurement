AC_PREREQ([2.69])
AC_INIT([c00clupeaperf], [01], [christoph.pohl0@hm.edu])
#AC_CONFIG_SRCDIR([src/config.c])
#AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([subdir-objects])
# Checks for programs.

AC_PROG_CC(clang gcc)

# this is for automakes beyond 1.14
AM_PROG_CC_C_O

AC_CHECK_HEADERS([stdio.h unistd.h stdlib.h time.h limits.h string.h pthread.h sys/wait.h])

AC_TYPE_SIZE_T

AC_FUNC_MALLOC

AC_CONFIG_HEADERS([src/conf.h])

AC_CONFIG_FILES([Makefile src/Makefile])

AC_COMPILE_IFELSE(
[AC_LANG_PROGRAM([], [[
#ifndef __clang__
       not clang
#endif
]])],
[CLANG=yes], [CLANG=no])

AC_MSG_RESULT([$CLANG])

AC_CANONICAL_HOST

AM_CONDITIONAL([ISDARWIN],false)
AM_CONDITIONAL([ISLINUX],false)

case $host_os in
  darwin* )
        AM_CONDITIONAL([NEEDPTHREAD],false)
	AM_CONDITIONAL([ISDARWIN],true)
	AC_DEFINE([OSDETECTED],[DARWIN],[darwin])
	AC_DEFINE([CLOCK_REALTIME],[0],[for clock_gettime fake])	
	AC_DEFINE([CLOCK_MONOTONIC],[0],[for clock_gettime fake])
        ;;
  linux*)
        AM_CONDITIONAL([NEEDPTHREAD],true)
	AM_CONDITIONAL([ISLINUX],true)	
	AC_DEFINE([OSDETECTED],[LINUX],[linux])	
        ;;
   *BSD*)
        AM_CONDITIONAL([NEEDPTHREAD],true)
	AC_DEFINE([OSDETECTED],[BSD],[openbsd/freebsd])	
        ;;
   *bsd*)
        AM_CONDITIONAL([NEEDPTHREAD],true)
	AC_DEFINE([OSDETECTED],[BSD],[openbsd/freebsd])	
        ;;
    *)

        AC_MSG_ERROR([Your platform is not currently supported])
        ;;
esac

if test "x$CLANG" = xyes; then
AM_CONDITIONAL([CLANG],true)
else
AM_CONDITIONAL([CLANG],false)
fi

AC_ARG_ENABLE([writecrap],
    AS_HELP_STRING([--enable-writecrap], [Enable really verbose output]))

AS_IF([test "$enable_writecrap" = "yes"], [
	AC_DEFINE([WRITEC00CRAP],[],[write really verbose stdouts])
])

AC_ARG_ENABLE([perfwithmain],
    AS_HELP_STRING([--enable-perfwithmain], [Enable main method in perf]))

AM_CONDITIONAL([PERFMAIN],false)

AS_IF([test "$enable_perfwithmain" = "yes"], [
	AC_DEFINE([PERFMAIN],[],[enable main method in perf])
	AM_CONDITIONAL([PERFMAIN],true)
])

AC_OUTPUT
