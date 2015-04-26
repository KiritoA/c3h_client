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
#define PRINTMSG(...) printf(__VA_ARGS__)
#else
#define PRINTMSG(...) fprintf(stderr, __VA_ARGS__)
#endif

#define PRINTERR(...) fprintf(stderr, __VA_ARGS__)

#ifdef WIN32
#define sleep(x)	Sleep(x*1000)
#endif

#endif //DEFS_H
