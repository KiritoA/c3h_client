/*
 * Filename:     defs.h
 *
 * Created by:	 liuqun
 * Revised by:   KiritoA
 * Description:  定义少量用于调试的宏函数
 *
 */

#ifndef DEFS_H
#define DEFS_H

#include <stdio.h>

#ifdef NDEBUG
#define PRINTDEBUG(...)
#else
#define PRINTDEBUG(...)	fprintf(stderr, __VA_ARGS__)
#endif

#ifdef WIN32
#define PRINT(...) printf(__VA_ARGS__)
#define PRINTMSG(...) printf(__VA_ARGS__)
#define PRINTERR(...) fprintf(stderr, __VA_ARGS__)
#else
#include <syslog.h>
#define PRINTMSG(format, ...) { \
			printf(format, ## __VA_ARGS__); \
			syslog(LOG_USER | LOG_INFO, format, ##__VA_ARGS__);  }

#define PRINTERR(format, ...) { \
			printf(format, ## __VA_ARGS__); \
			syslog(LOG_USER | LOG_ERR, format, ##__VA_ARGS__);  }

#define PRINT(...) printf(__VA_ARGS__)
#define LOGINFO(...) syslog(LOG_USER | LOG_INFO, __VA_ARGS__)
#define LOGERR(...) syslog(LOG_USER | LOG_ERR, __VA_ARGS__)
#endif

#define PUTCHAR(x) fputc(x, stderr)
#ifdef WIN32
#define sleep(x)	Sleep(x*1000)
#endif

#endif //DEFS_H
