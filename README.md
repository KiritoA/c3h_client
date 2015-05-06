c3h-client分支项目
===========
该项目是njit8021xclient的fork，是该项目的独立分支。

由于对njit8021xclient版本的结构和内容作出不少修改，在之前c3h-client是一个独立项目，现在决定直接归入njit8021xclient的fork项目并独立出一个新分支。

License
---------
本项目继承并遵循GPLv3协议，不欢迎任何用于商业却不公开源代码的行为(除非自行重写程序代码)

概述
-----
* 本项目基于njit8021xclient代码进行修改
* 基于iNode V7.00-0102版本的EAP报文分析进行修改
* 可运作于Linux/openWRT/Windows
* 集成MD5算法，不需要再依赖openssl
* 增加断线重连机制
* 测试环境为佛大
* 暂时未集成makefile，如有需要可修改使用njit8021xclient项目相关文件

依赖的开发包
--------
* Linux/openWRT: libpcap
* Windows: WinPcap(WpdPack)

测试日志
-----
jailbreak-test

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