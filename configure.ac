#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([mqtt], [0.0.1], [https://github.com/zhoukk/mqtt/issues])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SRCDIR([mqtt.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

LT_INIT

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lcrypto':
AC_CHECK_LIB([crypto], [-lcrypto])
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [-lpthread])
# FIXME: Replace `main' with a function in `-lssl':
AC_CHECK_LIB([ssl], [-lssl])
# FIXME: Replace `main' with a function in `-luv':
AC_CHECK_LIB([uv], [-luv])

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h limits.h stddef.h stdint.h stdlib.h string.h sys/time.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday memset strdup strncasecmp])

AC_ARG_ENABLE([debug], [AS_HELP_STRING([--enable-debug], [enable DEBUG mode [default=no]])], [CFLAGS="-DDEBUG -g2 -O0"], [CFLAGS="-O2"])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
