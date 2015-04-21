/*
 * Filename:     debug.h
 *
 * Created by:	 liuqun
 * Revised by:   KiritoA
 * Description:  定义少量用于调试的宏函数
 *
 */

#ifndef DEBUG_H
#define DEBUG_H

#	include <stdio.h>	// 导入函数原型fprintf(stderr,"%format",...)

/**
 * Macro: DPRINTF()
 *
 * Usage: 调用格式与printf()一致，支持变长参数表，例子如下：
 *
 * 	#include "debug.h"
 * 	...
 * 	int	errcode;
 * 	char	message[] = "xxx failed!";
 *	...
 * 	DPRINTF("Debug message: errcode=%d\n", errcode);
 * 	DPRINTF("Debug message: $s\n", message);
 *	exit(errcode);
 *
 * 在发布版中定义NDEBUG宏可以清除所有DPRINTF()信息
 * 注：宏NDEBUG源自C语言惯例
 *
 */
#ifdef NDEBUG
#	define PRINTDEBUG(...)
#else
#	define PRINTDEBUG(...)	fprintf(stderr, __VA_ARGS__)
#endif

#define PRINTMSG(...) fprintf(stderr, __VA_ARGS__)
#define PRINTERR(...) fprintf(stderr, __VA_ARGS__)

#endif // DEBUG_H
