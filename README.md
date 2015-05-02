c3h-client
===========
该项目代码源于以下项目：

njit8021xclient:https://github.com/liuqun/njit8021xclient

以及bitdust的fork:https://github.com/bitdust/njit8021xclient

由于对njit8021xclient版本的结构和内容作出不少修改，因此决定从该项目分离并建立一个新项目

License
---------
* 本项目继承并遵循GPLv3协议，不欢迎任何用于商业却不公开源代码的行为(卖校园网专用路由器的，除非自行重写程序代码)

概述
-----
* 本项目基于njit8021xclient代码进行修改
* 基于iNode V7.00-0102版本的EAP报文分析进行修改
* 可运作于Linux/openWRT/Windows
* 集成MD5算法，不需要再依赖openssl
* 测试环境为佛大
* 暂时未集成makefile，如有需要可修改使用njit8021xclient项目相关文件

依赖的开发包
--------
* Linux/openWRT: libpcap
* Windows: WinPcap(WpdPack)

测试日志
-----
* 2015.4.19：佛大校园网可成功认证，但校园网在心跳报文加入了某种检测，目前每7分钟会断线一次，之后可重新连接不会被拉黑。若为非佛大环境为保证正常使用请将auth.c中SendResponseSecurity()函数中找到
```
//response[i++] = 0x00;	// 上报是否使用代理，取消此处注释会导致马上断线拉黑
```
此行代码并取消注释

用法
-----
```
c3h-client  [username] [password] [adapter]
```
Linux/openWRT环境下可以不输入[adapter]参数，则默认设备为eth0
```
Usage:
c3h-client	[Username]	Your Username.
			[password]	Your Password.
			[adapter]	Specify ethernet adapter to use.
						Adapter in Linux is eth0,eth1...etc
						Adapter in Windows starts with '\Device\NPF_'
```

参考文献
---------
iNode协议逆向研究初步入门by tsy http://www.cnblogs.com/bitpeach/p/4092806.html