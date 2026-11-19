/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if we are enabling rule generator */
/* #undef ENABLE_RULE_GENERATOR */

/* Define if the tpm2_id builtin is enabled */
#define ENABLE_TPM2 1

/* The first ID of the foreign users and groups */
#define FOREIGN_UID_BASE 2147352576U

/* Define to the type of elements in the array argument to 'getgroups'.
   Usually this is either 'int' or 'gid_t'. */
#define GETGROUPS_T gid_t

/* Define to 1 if you have the 'alarm' function. */
#define HAVE_ALARM 1

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define if blkid is available */
#define HAVE_BLKID 1

/* Define to 1 if you have the 'blkid_probe_set_hint' function. */
#define HAVE_BLKID_PROBE_SET_HINT 1

/* Define to 1 if your system has a working 'chown' function. */
#define HAVE_CHOWN 1

/* Define to 1 if you have the declaration of 'accept4', and to 0 if you
   don't. */
#define HAVE_DECL_ACCEPT4 1

/* Define to 1 if you have the declaration of 'getrandom', and to 0 if you
   don't. */
#define HAVE_DECL_GETRANDOM 0

/* Define to 1 if you have the declaration of 'gettid', and to 0 if you don't.
   */
#define HAVE_DECL_GETTID 1

/* Define to 1 if you have the declaration of 'mkostemp', and to 0 if you
   don't. */
#define HAVE_DECL_MKOSTEMP 1

/* Define to 1 if you have the declaration of 'name_to_handle_at', and to 0 if
   you don't. */
#define HAVE_DECL_NAME_TO_HANDLE_AT 1

/* Define to 1 if you have the declaration of 'ppoll', and to 0 if you don't.
   */
#define HAVE_DECL_PPOLL 1

/* Define to 1 if you have the declaration of 'strerror_r', and to 0 if you
   don't. */
#define HAVE_DECL_STRERROR_R 1

/* Define to 1 if you have the declaration of 'strndupa', and to 0 if you
   don't. */
#define HAVE_DECL_STRNDUPA 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the 'dup2' function. */
#define HAVE_DUP2 1

/* Define to 1 if you have the 'explicit_bzero' function. */
#define HAVE_EXPLICIT_BZERO 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the 'fork' function. */
#define HAVE_FORK 1

/* Define to 1 if fseeko (and ftello) are declared in stdio.h. */
#define HAVE_FSEEKO 1

/* Define to 1 if you have the 'ftruncate' function. */
#define HAVE_FTRUNCATE 1

/* Define to 1 if your system has a working 'getgroups' function. */
#define HAVE_GETGROUPS 1

/* Define to 1 if you have the 'getpagesize' function. */
#define HAVE_GETPAGESIZE 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define if kmod is available */
#define HAVE_KMOD 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the <linux/btrfs.h> header file. */
#define HAVE_LINUX_BTRFS_H 1

/* Define to 1 if you have the <linux/ioprio.h> header file. */
#define HAVE_LINUX_IOPRIO_H 1

/* Define to 1 if you have the <locale.h> header file. */
#define HAVE_LOCALE_H 1

/* Define to 1 if you have the 'localtime_r' function. */
#define HAVE_LOCALTIME_R 1

/* Define to 1 if you have the 'mallinfo' function. */
#define HAVE_MALLINFO 1

/* Define to 1 if you have the 'mallinfo2' function. */
#define HAVE_MALLINFO2 1

/* Define to 1 if you have the 'mempcpy' function. */
#define HAVE_MEMPCPY 1

/* Define to 1 if you have the <minix/config.h> header file. */
/* #undef HAVE_MINIX_CONFIG_H */

/* Define to 1 if you have the 'mkdir' function. */
#define HAVE_MKDIR 1

/* Define to 1 if you have a working 'mmap' system call. */
#define HAVE_MMAP 1

/* Define to 1 if you have the <mtd/mtd-user.h> header file. */
#define HAVE_MTD_MTD_USER_H 1

/* Define to 1 if you have the 'munmap' function. */
#define HAVE_MUNMAP 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have the 'nl_langinfo' function. */
#define HAVE_NL_LANGINFO 1

/* Define to 1 if you have the 'rmdir' function. */
#define HAVE_RMDIR 1

/* Define to 1 if you have the 'secure_getenv' function. */
#define HAVE_SECURE_GETENV 1

/* Define if SELinux is available */
/* #undef HAVE_SELINUX */

/* Define to 1 if you have the 'setlocale' function. */
#define HAVE_SETLOCALE 1

/* Define if SMACK support is enabled */
/* #undef HAVE_SMACK */

/* Define to 1 if you have the 'socket' function. */
#define HAVE_SOCKET 1

/* Define to include hard-coded default search paths in / and /usr */
/* #undef HAVE_SPLIT_USR */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the 'stpcpy' function. */
#define HAVE_STPCPY 1

/* Define if you have 'strerror_r'. */
#define HAVE_STRERROR_R 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if 'st_rdev' is a member of 'struct stat'. */
#define HAVE_STRUCT_STAT_ST_RDEV 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/mount.h> header file. */
#define HAVE_SYS_MOUNT_H 1

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/statvfs.h> header file. */
#define HAVE_SYS_STATVFS_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/vfs.h> header file. */
#define HAVE_SYS_VFS_H 1

/* Define to 1 if you have the <termios.h> header file. */
#define HAVE_TERMIOS_H 1

/* Define to 1 if you have the 'uname' function. */
#define HAVE_UNAME 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define if unshare is declared */
#define HAVE_UNSHARE 1

/* Define to 1 if you have the 'vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if you have the <vfork.h> header file. */
/* #undef HAVE_VFORK_H */

/* Define to 1 if you have the <wchar.h> header file. */
#define HAVE_WCHAR_H 1

/* Define to 1 if 'fork' works. */
#define HAVE_WORKING_FORK 1

/* Define to 1 if 'vfork' works. */
#define HAVE_WORKING_VFORK 1

/* Define to 1 if 'lstat' dereferences a symlink specified with a trailing
   slash. */
#define LSTAT_FOLLOWS_SLASHED_SYMLINK 1

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Define to 1 if 'major', 'minor', and 'makedev' are declared in <mkdev.h>.
   */
/* #undef MAJOR_IN_MKDEV */

/* Define to 1 if 'major', 'minor', and 'makedev' are declared in
   <sysmacros.h>. */
#define MAJOR_IN_SYSMACROS 1

/* The name of the group with the GID 65534 */
#define NOBODY_GROUP_NAME "nobody"

/* The name of the user with the UID 65534 */
#define NOBODY_USER_NAME "nobody"

/* Name of package */
#define PACKAGE "eudev"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://github.com/eudev-project/eudev/issues"

/* Define to the full name of this package. */
#define PACKAGE_NAME "eudev"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "eudev 3.3.0"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "eudev"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "3.3.0"

/* The size of 'dev_t', as computed by sizeof. */
#define SIZEOF_DEV_T 8

/* The size of 'gid_t', as computed by sizeof. */
#define SIZEOF_GID_T 4

/* The size of 'pid_t', as computed by sizeof. */
#define SIZEOF_PID_T 4

/* The size of 'rlim_t', as computed by sizeof. */
#define SIZEOF_RLIM_T 8

/* The size of 'uid_t', as computed by sizeof. */
#define SIZEOF_UID_T 4

/* Define to 1 if all of the C89 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#define STDC_HEADERS 1

/* Define to 1 if strerror_r returns char *. */
#define STRERROR_R_CHAR_P 1

/* The highest group ID of system groups */
#define SYSTEM_GID_MAX 999

/* The highest user ID of system users */
#define SYSTEM_UID_MAX 999

/* Enable extensions on AIX, Interix, z/OS.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable extensions on Cosmopolitan Libc. */
#ifndef _COSMO_SOURCE
# define _COSMO_SOURCE 1
#endif
/* Enable general extensions on macOS.  */
#ifndef _DARWIN_C_SOURCE
# define _DARWIN_C_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable X/Open compliant socket functions that do not require linking
   with -lxnet on HP-UX 11.11.  */
#ifndef _HPUX_ALT_XOPEN_SOCKET_API
# define _HPUX_ALT_XOPEN_SOCKET_API 1
#endif
/* Identify the host operating system as Minix.
   This macro does not affect the system headers' behavior.
   A future release of Autoconf may stop defining this macro.  */
#ifndef _MINIX
/* # undef _MINIX */
#endif
/* Enable general extensions on NetBSD.
   Enable NetBSD compatibility extensions on Minix.  */
#ifndef _NETBSD_SOURCE
# define _NETBSD_SOURCE 1
#endif
/* Enable OpenBSD compatibility extensions on NetBSD.
   Oddly enough, this does nothing on OpenBSD.  */
#ifndef _OPENBSD_SOURCE
# define _OPENBSD_SOURCE 1
#endif
/* Define to 1 if needed for POSIX-compatible behavior.  */
#ifndef _POSIX_SOURCE
/* # undef _POSIX_SOURCE */
#endif
/* Define to 2 if needed for POSIX-compatible behavior.  */
#ifndef _POSIX_1_SOURCE
/* # undef _POSIX_1_SOURCE */
#endif
/* Enable POSIX-compatible threading on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-5:2014.  */
#ifndef __STDC_WANT_IEC_60559_ATTRIBS_EXT__
# define __STDC_WANT_IEC_60559_ATTRIBS_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-1:2014.  */
#ifndef __STDC_WANT_IEC_60559_BFP_EXT__
# define __STDC_WANT_IEC_60559_BFP_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-2:2015.  */
#ifndef __STDC_WANT_IEC_60559_DFP_EXT__
# define __STDC_WANT_IEC_60559_DFP_EXT__ 1
#endif
/* Enable extensions specified by C23 Annex F.  */
#ifndef __STDC_WANT_IEC_60559_EXT__
# define __STDC_WANT_IEC_60559_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-4:2015.  */
#ifndef __STDC_WANT_IEC_60559_FUNCS_EXT__
# define __STDC_WANT_IEC_60559_FUNCS_EXT__ 1
#endif
/* Enable extensions specified by C23 Annex H and ISO/IEC TS 18661-3:2015.  */
#ifndef __STDC_WANT_IEC_60559_TYPES_EXT__
# define __STDC_WANT_IEC_60559_TYPES_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TR 24731-2:2010.  */
#ifndef __STDC_WANT_LIB_EXT2__
# define __STDC_WANT_LIB_EXT2__ 1
#endif
/* Enable extensions specified by ISO/IEC 24747:2009.  */
#ifndef __STDC_WANT_MATH_SPEC_FUNCS__
# define __STDC_WANT_MATH_SPEC_FUNCS__ 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable X/Open extensions.  Define to 500 only if necessary
   to make mbstate_t available.  */
#ifndef _XOPEN_SOURCE
/* # undef _XOPEN_SOURCE */
#endif


/* Version number of package */
#define VERSION "3.3.0"

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define to 1 if necessary to make fseeko visible. */
/* #undef _LARGEFILE_SOURCE */

/* Define to 1 on platforms where this makes off_t a 64-bit type. */
/* #undef _LARGE_FILES */

/* Number of bits in time_t, on hosts where this is settable. */
/* #undef _TIME_BITS */

/* Define to 1 on platforms where this makes time_t a 64-bit type. */
/* #undef __MINGW_USE_VC2005_COMPAT */

/* Define as 'int' if <sys/types.h> doesn't define. */
/* #undef gid_t */

/* Define to '__inline__' or '__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to 'int' if <sys/types.h> does not define. */
/* #undef mode_t */

/* Define as a signed integer type capable of holding a process identifier. */
/* #undef pid_t */

/* Define as 'int' if <sys/types.h> doesn't define. */
/* #undef uid_t */

/* Define as 'fork' if 'vfork' does not work. */
/* #undef vfork */
