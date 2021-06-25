MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES =

AM_CFLAGS = -Werror=attributes \
  -I$(srcdir) \
  -I$(top_srcdir) \
  $(libuv_CFLAGS) \
  $(libnghttp2_CFLAGS)

pkglibdir = $(libdir)/lua/5.1/$(PACKAGE)
pkglib_LTLIBRARIES = dnssim.la
dnssim_la_SOURCES = output/dnssim.c output/dnssim/https2.c \
  output/dnssim/common.c output/dnssim/connection.c output/dnssim/udp.c \
  output/dnssim/tcp.c output/dnssim/tls.c
dist_dnssim_la_SOURCES = output/dnssim/ll.h output/dnssim/internal.h
dnssim_la_LDFLAGS = -Wl,-E -module -avoid-version -shared $(libuv_LIBS) $(libnghttp2_LIBS)

dnssimlibdir = $(datadir)/lua/5.1/shotgun/output
dist_dnssimlib_DATA = output/dnssim.lua
