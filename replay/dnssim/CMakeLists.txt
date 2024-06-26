cmake_minimum_required(VERSION 3.5)
project(dnssim C)

include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckFunctionExists)

option(DNSJIT_PATH "Path to dnsjit prefix" "")
option(ASAN "Use AddressSanitizer" OFF)
option(UBSAN "Use UndefinedBehaviorSanitizer" OFF)
option(USE_SYSTEM_NGTCP2 "Use ngtcp2 from the system" OFF)


## Dependencies ################################################################

# GnuTLS
find_package(GnuTLS REQUIRED)
list(APPEND DNSSIM_LIBS GnuTLS::GnuTLS)

# LibUV
find_library(LIBUV_LIB libuv.so REQUIRED)
list(APPEND DNSSIM_LIBS ${LIBUV_LIB})
check_include_file(uv.h HAS_UV_H)
if (NOT HAS_UV_H)
	message(FATAL_ERROR "LibUV is required")
endif ()

# nghttp2
find_library(NGHTTP2_LIB libnghttp2.so REQUIRED)
list(APPEND DNSSIM_LIBS ${NGHTTP2_LIB})
check_include_file(nghttp2/nghttp2.h HAS_NGHTTP2_H)
if (NOT HAS_NGHTTP2_H)
	message(FATAL_ERROR "nghttp2 is required")
endif ()

# ngtcp2
if (USE_SYSTEM_NGTCP2)
	find_library(NGTCP2_LIB libngtcp2.so REQUIRED)
	list(APPEND DNSSIM_LIBS ${NGTCP2_LIB})
	find_library(NGTCP2_GTLS_LIB libngtcp2_crypto_gnutls.so REQUIRED)
	list(APPEND DNSSIM_LIBS ${NGTCP2_GTLS_LIB})
	check_include_files("ngtcp2/ngtcp2.h;ngtcp2/ngtcp2_crypto.h;ngtcp2/ngtcp2_crypto_gnutls.h"
		HAS_NGTCP2_H)

	if (NOT HAS_NGTCP2_H)
		message(FATAL_ERROR "ngtcp2 is required (and set to use system)")
	endif ()
else ()
	function (add_ngtcp2) # wrapped in a function to ensure scope
		list(APPEND CMAKE_C_FLAGS -fPIC)
		set(ENABLE_STATIC_LIB ON)
		set(ENABLE_GNUTLS ON)
		set(ENABLE_QUICTLS OFF)
		set(ENABLE_OPENSSL OFF)
		add_subdirectory(vendor/ngtcp2 EXCLUDE_FROM_ALL SYSTEM)
	endfunction ()
	add_ngtcp2()
	list(APPEND DNSSIM_LIBS ngtcp2_static)
	list(APPEND DNSSIM_LIBS ngtcp2_crypto_gnutls_static)
endif ()

# dnsjit
if (DNSJIT_PATH)
	include_directories(${DNSJIT_PATH}/include)
endif ()
check_include_file(dnsjit/version.h HAS_DNSJIT_H)
if (NOT HAS_DNSJIT_H)
	message(FATAL_ERROR "dnsjit is required (you may use DNSJIT_PATH to specify its install prefix)")
endif ()

# syscalls
check_function_exists(clock_gettime HAS_CLOCK_GETTIME)
check_function_exists(clock_nanosleep HAS_CLOCK_NANOSLEEP)
if (NOT HAS_CLOCK_GETTIME OR NOT HAS_CLOCK_NANOSLEEP)
	message(FATAL_ERROR "clock_gettime() and clock_nanosleep() are required")
endif ()


## Sanitizers ##################################################################

if (ASAN)
	list(APPEND DNSSIM_SANITIZERS address)
endif ()
if (UBSAN)
	list(APPEND DNSSIM_SANITIZERS undefined)
endif ()

if (DNSSIM_SANITIZERS)
	list(JOIN DNSSIM_SANITIZERS "," DNSSIM_SANITIZERS_JOINED)
	list(APPEND CMAKE_C_FLAGS -fsanitize=${DNSSIM_SANITIZERS_JOINED})
endif ()


## DNSSIM ######################################################################

list(APPEND DNSSIM_OPTS -fno-strict-aliasing -Wall)
include_directories(src)
add_library(dnssim SHARED
	src/output/dnssim.c
	src/output/dnssim/common.c
	src/output/dnssim/connection.c
	src/output/dnssim/https2.c
	src/output/dnssim/quic.c
	src/output/dnssim/tcp.c
	src/output/dnssim/tls.c
	src/output/dnssim/udp.c
	)
target_link_libraries(dnssim PUBLIC ${DNSSIM_LIBS})
set_target_properties(dnssim PROPERTIES
	PREFIX "")
target_link_options(dnssim PUBLIC ${DNSSIM_OPTS})
target_compile_options(dnssim PUBLIC ${DNSSIM_OPTS})


## Install #####################################################################

install(TARGETS dnssim
	DESTINATION lib/lua/5.1/shotgun-output-dnssim/)
install(FILES src/output/dnssim.lua
	DESTINATION share/lua/5.1/shotgun/output/)
