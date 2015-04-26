/*
 * Filename:     main.c
 *
 * Created by:	 liuqun
 * Revised by:   KiritoA
 * Description:  校园网802.1X客户端命令行
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>

#ifndef WIN32
#include <unistd.h>
#endif

#include "defs.h"
#include "auth.h"
#include "adapter.h"

void signal_interrupted (int signo)
{
    LogOff();
	CloseDevice();
    exit(0);
}

void showUsage()
{
	PRINTMSG("C3H Client\n"
		"Usage:\n"
		"\tc3h-client [username] [password] [adapter]\n"
		"\t[Username] Your Username.\n"
		"\t[password] Your Password.\n"
		"\t[adapter]  Specify ethernet adapter to use.\n"
		"\t           Adapter in Linux is eth0,eth1...etc\n"
		"\t           Adapter in Windows starts with '\\Device\\NPF_'\n\n");
}

/**
 * 函数：main()
 *
 */
int main(int argc, char *argv[])
{
	int ret;
	bool autoReconnect = true;
	char *UserName;
	char *Password;
	char *DeviceName;
#ifndef WIN32
	/* 检查当前是否具有root权限 */
	if (getuid() != 0) {
		PRINTMSG( "抱歉，运行本客户端程序需要root权限\n");
		PRINTMSG( "(RedHat/Fedora下使用su命令切换为root)\n");
		PRINTMSG( "(Ubuntu/Debian下在命令前添加sudo)\n");
		exit(-1);
	}
	/* 检查命令行参数格式 */
	if (argc<3 || argc>4) {
		showUsage();
		ListAllAdapters();
		exit(-1);
	} else if (argc == 4) {
		DeviceName = argv[3]; // 允许从命令行指定设备名
	} else {
		DeviceName = "eth0"; // 缺省情况下使用的设备
	}
#else
	/* 检查命令行参数格式 */
	if (argc != 4) {

		showUsage();
		ListAllAdapters();
		exit(-1);
	}
	else {
		DeviceName = argv[3]; // 允许从命令行指定设备名
	}
#endif

	UserName = argv[1];
	Password = argv[2];

	InitDevice(DeviceName);

	//此时开始按下Ctrl+C可退出程序
	signal(SIGINT, signal_interrupted);

	int retry = 0;
	time_t lastAuthTime;
	do
	{
		lastAuthTime = time(NULL);
		/* 调用子函数完成802.1X认证 */
		ret = Authentication(UserName, Password);
		if (ret == ERR_NOT_RESPOND)
		{
			PRINTMSG("C3H Client: Connection Failed. Code:%d\n", ret);
			break;
		}
		else if (ret == 0 || ret == ERR_AUTH_TIME_LIMIT)
		{
			PRINTMSG("C3H Client: Connection closed.\n");
			break;
		}
		else
		{
			if ((time(NULL) - lastAuthTime) < 60)
			{
				sleep(60);
			}
			sleep(5);
			PRINTMSG("C3H Client: Reconnecting...[%d]\n", ++retry);
		}
			

	} while (autoReconnect);
	CloseDevice();
	return (0);
}

