/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* Define DLT_LINUX_SLL if not defined by the system */
/* #undef DLT_LINUX_SLL */

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if you have the `calloc' function. */
#define HAVE_CALLOC 1

/* Whether _cmocka_run_group_tests() is provided by the cmocka library */
#define HAVE_CMOCKA_RUN_GROUP_TESTS 1

/* Whether _run_tests() is provided by the cmocka library */
#define HAVE_CMOCKA_RUN_TESTS 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the `free' function. */
#define HAVE_FREE 1

/* Define to 1 if you have the `htonl' function. */
#define HAVE_HTONL 1

/* Define to 1 if you have the `htons' function. */
#define HAVE_HTONS 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `malloc' function. */
#define HAVE_MALLOC 1

/* Define to 1 if you have the `memcmp' function. */
#define HAVE_MEMCMP 1

/* Define to 1 if you have the `memcpy' function. */
#define HAVE_MEMCPY 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `ntohl' function. */
#define HAVE_NTOHL 1

/* Define to 1 if you have the `ntohs' function. */
#define HAVE_NTOHS 1

/* Define to 1 if you have the <pcap.h> header file. */
#define HAVE_PCAP_H 1

/* Define to 1 if you have the <pcap/pcap.h> header file. */
#define HAVE_PCAP_PCAP_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the <winsock2.h> header file. */
/* #undef HAVE_WINSOCK2_H */

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Name of package */
#define PACKAGE "rohc"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://rohc-lib.org/"

/* Define to the full name of this package. */
#define PACKAGE_NAME "ROHC library"

/* VCS revision number */
#define PACKAGE_REVNO ""

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "ROHC library 2.1.0"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "rohc"

/* Define to the home page for this package. */
#define PACKAGE_URL "https://rohc-lib.org/"

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.1.0"

/* Extra debug traces for ROHC library */
#define ROHC_EXTRA_DEBUG 1

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Version number of package */
#define VERSION "2.1.0"

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Define for Solaris 2.5.1 so the uint32_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT32_T */

/* Define for Solaris 2.5.1 so the uint8_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT8_T */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to the type of an unsigned integer type of width exactly 16 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint16_t */

/* Define to the type of an unsigned integer type of width exactly 32 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint32_t */

/* Define to the type of an unsigned integer type of width exactly 8 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint8_t */
