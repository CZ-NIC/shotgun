AC_PREREQ(2.61)
AC_INIT([shotgun-output-dnssim], [20210129],,)
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_HEADER([src/config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_CANONICAL_HOST
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT([disable-static])

# Check for dnsjit development files
AC_ARG_WITH([dnsjit], [AS_HELP_STRING([--with-dnsjit=PATH], [Use PATH when checking for dnsjit development files])], [
  AS_VAR_APPEND(CFLAGS, [" -I$withval/include"])
])
AC_CHECK_HEADER([dnsjit/version.h],, [AC_MSG_ERROR([dnsjit development headers not found])])

# Check for dependencies
PKG_CHECK_MODULES([libuv], [libuv])
PKG_CHECK_MODULES([libnghttp2], [libnghttp2])
AC_CHECK_LIB([gnutls], [gnutls_init],, [AC_MSG_ERROR([libgnutls not found])])

# Checks for support.
AC_SEARCH_LIBS([clock_gettime])
AC_CHECK_FUNCS([clock_nanosleep nanosleep])

# Output Makefiles
AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_OUTPUT
