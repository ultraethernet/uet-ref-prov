/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/*
 * NOTE that a '\n' is automatically appended to all printf strings!
 * No need to add one yourself. :-)
 *
 * The following printf/LOG macros are defined for each UET layer:
 *
 *     UET_[SES|PDS|TSS]_DBG(fmt, ...)
 *     UET_[SES|PDS|TSS]_INFO(fmt, ...)
 *     UET_[SES|PDS|TSS]_WARN(fmt, ...)
 *     UET_[SES|PDS|TSS]_ERR(fmt, ...)
 *
 * The LOGs for each UET layer are enabled by default. Each layer can be
 * disabled independently by undefining UET_LOG_[SES|PDS|TSS].
 *
 * The ERR and WARN logs also print the file and line number where the
 * error/warning hit.
 *
 * Colors are enabled by default and each UET layer has its own color. ERR
 * and WARN logs are printed in their own color, regardless of the UET layer.
 * Colors can be disabled by undefining UET_LOG_EN_CLR.
 */

#include <stdio.h>

#define UET_LOG_EN_CLR /* comment out to disable log colors */

#define UET_LOG_SES /* comment out to disable all SES logs */
#define UET_LOG_PDS /* comment out to disable all PDS logs */
#define UET_LOG_TSS /* comment out to disable all TSS logs */

#define UET_LOG_ERR  1
#define UET_LOG_WARN 2
#define UET_LOG_INFO 3
#define UET_LOG_DBG  4
#define UET_LOG_LVL  UET_LOG_DBG /* max log level to print (+below) */

#define UET_SES_LBL "[SES] "
#define UET_PDS_LBL "[PDS] "
#define UET_TSS_LBL "[TSS] "

#ifdef UET_LOG_EN_CLR
# define UET_CLR_NORMAL  "\x1b[m"
# define UET_CLR_BLACK   "\x1b[30m"
# define UET_CLR_RED     "\x1b[31m"
# define UET_CLR_GREEN   "\x1b[32m"
# define UET_CLR_YELLOW  "\x1b[33m"
# define UET_CLR_BLUE    "\x1b[34m"
# define UET_CLR_MAGENTA "\x1b[35m"
# define UET_CLR_CYAN    "\x1b[36m"
# define UET_CLR_WHITE   "\x1b[37m"
#else
# define UET_CLR_NORMAL  ""
# define UET_CLR_BLACK   ""
# define UET_CLR_RED     ""
# define UET_CLR_GREEN   ""
# define UET_CLR_YELLOW  ""
# define UET_CLR_BLUE    ""
# define UET_CLR_MAGENTA ""
# define UET_CLR_CYAN    ""
# define UET_CLR_WHITE   ""
#endif

#define UET_SES_CLR UET_CLR_CYAN
#define UET_PDS_CLR UET_CLR_MAGENTA
#define UET_TSS_CLR UET_CLR_GREEN

#define UET_WARN_CLR UET_CLR_YELLOW
#define UET_ERR_CLR  UET_CLR_RED

#define UET_LOG(fmt, clr, ...)          \
	do {                            \
		printf("%s" fmt "%s\n", \
		       (clr),           \
		       ##__VA_ARGS__,   \
		       UET_CLR_NORMAL); \
		fflush(stdout);         \
	} while (0)

#define UET_DBG(fmt, clr, ...)               \
	do {                                 \
		printf("%sDBG: " fmt "%s\n", \
		       (clr),                \
		       ##__VA_ARGS__,        \
		       UET_CLR_NORMAL);      \
		fflush(stdout);              \
	} while (0)

#define UET_INFO(fmt, clr, ...)               \
	do {                                  \
		printf("%sINFO: " fmt "%s\n", \
		       (clr),                 \
		       ##__VA_ARGS__,         \
		       UET_CLR_NORMAL);       \
		fflush(stdout);               \
	} while (0)

#define UET_WARN(fmt, ...)                            \
	do {                                          \
		printf("%s[%s:%d] WARN: " fmt "%s\n", \
		       UET_WARN_CLR,                  \
		       __FILE__, __LINE__,            \
		       ##__VA_ARGS__,                 \
		       UET_CLR_NORMAL);               \
		fflush(stdout);                       \
	} while (0)

#define UET_ERR(fmt, ...)                              \
	do {                                           \
		printf("%s[%s:%d] ERROR: " fmt "%s\n", \
		       UET_ERR_CLR,                    \
		       __FILE__, __LINE__,             \
		       ##__VA_ARGS__,                  \
		       UET_CLR_NORMAL);                \
		fflush(stdout);                        \
	} while (0)

#if UET_LOG_LVL >= UET_LOG_DBG
# ifdef UET_LOG_SES
#  define UET_SES_DBG(fmt, ...) UET_DBG(UET_SES_LBL fmt, UET_SES_CLR, ##__VA_ARGS__)
# else
#  define UET_SES_DBG(...)
# endif
# ifdef UET_LOG_PDS
#  define UET_PDS_DBG(fmt, ...) UET_DBG(UET_PDS_LBL fmt, UET_PDS_CLR, ##__VA_ARGS__)
# else
#  define UET_PDS_DBG(...)
# endif
# ifdef UET_LOG_TSS
#  define UET_TSS_DBG(fmt, ...) UET_DBG(UET_TSS_LBL fmt, UET_TSS_CLR, ##__VA_ARGS__)
# else
#  define UET_TSS_DBG(...)
# endif
#else
# define UET_SES_DBG(...)
# define UET_PDS_DBG(...)
# define UET_TSS_DBG(...)
#endif

#if UET_LOG_LVL >= UET_LOG_INFO
# ifdef UET_LOG_SES
#  define UET_SES_INFO(fmt, ...) UET_INFO(UET_SES_LBL fmt, UET_SES_CLR, ##__VA_ARGS__)
# else
#  define UET_SES_INFO(...)
# endif
# ifdef UET_LOG_PDS
#  define UET_PDS_INFO(fmt, ...) UET_INFO(UET_PDS_LBL fmt, UET_PDS_CLR, ##__VA_ARGS__)
# else
#  define UET_PDS_INFO(...)
# endif
# ifdef UET_LOG_TSS
#  define UET_TSS_INFO(fmt, ...) UET_INFO(UET_TSS_LBL fmt, UET_TSS_CLR, ##__VA_ARGS__)
# else
#  define UET_TSS_INFO(...)
# endif
#else
# define UET_SES_INFO(...)
# define UET_PDS_INFO(...)
# define UET_TSS_INFO(...)
#endif

#if UET_LOG_LVL >= UET_LOG_WARN
# ifdef UET_LOG_SES
#  define UET_SES_WARN(fmt, ...) UET_WARN(UET_SES_LBL fmt, ##__VA_ARGS__)
# else
#  define UET_SES_WARN(...)
# endif
# ifdef UET_LOG_PDS
#  define UET_PDS_WARN(fmt, ...) UET_WARN(UET_PDS_LBL fmt, ##__VA_ARGS__)
# else
#  define UET_PDS_WARN(...)
# endif
# ifdef UET_LOG_TSS
#  define UET_TSS_WARN(fmt, ...) UET_WARN(UET_TSS_LBL fmt, ##__VA_ARGS__)
# else
#  define UET_TSS_WARN(...)
# endif
#else
# define UET_SES_WARN(...)
# define UET_PDS_WARN(...)
# define UET_TSS_WARN(...)
#endif

#if UET_LOG_LVL >= UET_LOG_ERR
# ifdef UET_LOG_SES
#  define UET_SES_ERR(fmt, ...) UET_ERR(UET_SES_LBL fmt, ##__VA_ARGS__)
# else
#  define UET_SES_ERR(...)
# endif
# ifdef UET_LOG_PDS
#  define UET_PDS_ERR(fmt, ...) UET_ERR(UET_PDS_LBL fmt, ##__VA_ARGS__)
# else
#  define UET_PDS_ERR(...)
# endif
# ifdef UET_LOG_TSS
#  define UET_TSS_ERR(fmt, ...) UET_ERR(UET_TSS_LBL fmt, ##__VA_ARGS__)
# else
#  define UET_TSS_ERR(...)
# endif
#else
# define UET_SES_ERR(...)
# define UET_PDS_ERR(...)
# define UET_TSS_ERR(...)
#endif

