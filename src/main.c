/*
 * Filename:     main.c
 *
 * Created by:	 liuqun
 * Revised by:   KiritoA
 * Description:  校园网802.1X客户端程序入口
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>

#ifndef WIN32
#include <unistd.h>
#endif

#include "defs.h"
#include "auth.h"
#include "adapter.h"

#define ARG_NUMBER	4
#define ABOUT_INFO_STRING "C3H Client 15.12j\n"

void signal_interrupted (int signo)
{
    LogOff();
	CloseDevice();
    exit(0);
}

void showUsage()
{
	PRINT("C3H Client\n"
		"Usage:\n"
		"\tc3h-client [username] [password] [adapter] [reconnect]\n"
		"\t[Username]   Your Username.\n"
		"\t[password]   Your Password.\n"
		"\t[adapter]    Specify ethernet adapter to use.\n"
		"\t             Adapter in Linux is eth0,eth1,...etc\n"
		"\t             Adapter in Windows starts with '\\Device\\NPF_'\n"
		"\t[reconnect]  Times to reconnect after failure. value 0 will disable reconnection feature.\n\n");
}

/**
 * 函数：main()
 *
 */
int main(int argc, char *argv[])
{
	int ret;
	char *UserName;
	char *Password;
	char *DeviceName;
	char *Reconnect;

#ifndef WIN32
	/* 检查当前是否具有root权限 */
	if (getuid() != 0) {
		PRINT( "抱歉，运行本客户端程序需要root权限\n");
		PRINT( "(RedHat/Fedora下使用su命令切换为root)\n");
		PRINT( "(Ubuntu/Debian下在命令前添加sudo)\n");
		exit(-1);
	}
#endif
	/* 检查命令行参数格式 */
	if (argc != ARG_NUMBER+1) {

		showUsage();
		ListAllAdapters();
		exit(-1);
	}

	UserName = argv[1];
	Password = argv[2];
	DeviceName = argv[3]; // 允许从命令行指定设备名
	Reconnect = argv[4];//重连次数

	int i;

	for (i = 0; i < (int)strlen(Reconnect); i++)
	{
		if (Reconnect[i]<'0' || Reconnect[i]>'9')
		{
			PRINTERR("Invalid reconnect value.\r");
			exit(-1);
		}
	}

	InitDevice(DeviceName);

	//此时开始按下Ctrl+C可退出程序
	signal(SIGINT, signal_interrupted);

	PRINTMSG(ABOUT_INFO_STRING);

	int overheat = 0;
	int retry = 0;
	int success = 0;
	int failure = 0;

	int reconnect = 0;
	reconnect = atoi(Reconnect);

	time_t lastAuthTime;
	do
	{
		lastAuthTime = time(NULL);
		/* 调用子函数完成802.1X认证 */
		ret = Authentication(UserName, Password);

		if (ret == ERR_AUTH_MAC_FAILED)
		{
			PRINTERR("C3H Client: Connection Failed(Code:%d).\n", ret);
			break;
		}
		else if (ret == 0 || ret == ERR_AUTH_TIME_LIMIT)
		{
			PRINTERR("C3H Client: Connection closed.\n");
			break;
		}
		else
		{
			PRINTERR("C3H Client: Connection Failed(Code:%d).\n", ret);

			if (ret == ERR_FAILED_AFTER_SUCCESS)
			{
				reconnect = atoi(Reconnect);//重置重连计数
				success++;
				retry = 0;
			}
			else
			{
				failure++;
			}

			if(reconnect == 0)
				break;

			if ((time(NULL) - lastAuthTime) < 20 && ++overheat > 3)
			{
					PRINTMSG("C3H Client: Wait for 20s...\n");
					sleep(20);
					overheat = 0;
			}
			else
				sleep(5);

			retry++;
			PRINTMSG("C3H Client: Reconnecting...[S:%d F:%d R:%d]\n", success, failure, retry);
		}
	} while (reconnect--);
	CloseDevice();
	PRINTMSG("C3H Client: Exit.[S:%d F:%d R:%d]\n", success, failure, retry);
	return (0);
}

