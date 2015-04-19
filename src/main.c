/*
 * Filename:     main.c
 *
 * Created by:	 liuqun
 * Revised:      2015年4月19日
 * Revised by:   KiritoA
 * Description:  校园网802.1X客户端命令行
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#ifndef WIN32
#include <unistd.h>
#endif

#include "auth.h"
#include "adapter.h"

void signal_interrupted (int signo)
{
    LogOff();
    exit(0);
}

/**
 * 函数：main()
 *
 */
int main(int argc, char *argv[])
{
	char *UserName;
	char *Password;
	char *DeviceName;
#ifndef WIN32
	/* 检查当前是否具有root权限 */
	if (getuid() != 0) {
		fprintf(stderr, "抱歉，运行本客户端程序需要root权限\n");
		fprintf(stderr, "(RedHat/Fedora下使用su命令切换为root)\n");
		fprintf(stderr, "(Ubuntu/Debian下在命令前添加sudo)\n");
		exit(-1);
	}
	/* 检查命令行参数格式 */
	if (argc<3 || argc>4) {
		fprintf(stderr, "命令行参数错误！\n");
		fprintf(stderr,	"正确的调用格式例子如下：\n");
		fprintf(stderr,	"    %s username password\n", argv[0]);
		fprintf(stderr,	"    %s username password eth0\n", argv[0]);
		fprintf(stderr,	"    %s username password eth1\n", argv[0]);
		fprintf(stderr, "(注：若不指明网卡，默认情况下将使用eth0)\n");
		exit(-1);
	} else if (argc == 4) {
		DeviceName = argv[3]; // 允许从命令行指定设备名
	} else {
		DeviceName = "eth0"; // 缺省情况下使用的设备
	}
#else
	/* 检查命令行参数格式 */
	if (argc != 4) {
		fprintf(stderr, "Usage:\n");
		fprintf(stderr, "c3h-client [username] [password] [adapter]\n\n", argv[0]);
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

	/* 调用子函数完成802.1X认证 */
	Authentication(UserName, Password, DeviceName);

	return (0);
}

