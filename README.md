c3h-client
===========
该项目代码源于以下项目：

njit8021xclient:https://github.com/liuqun/njit8021xclient

以及bitdust的fork:https://github.com/bitdust/njit8021xclient

由于对njit8021xclient版本的结构和内容作出不少修改，因此决定从该项目分离并建立一个新项目

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
c3h-client  [username] [password] [adapter] [reconnect]

[Username]	用户名
[password]	密码
[adapter]	认证网卡。
			Linux中网卡为eth0,eth1...
			Windows中网卡以"\Device\NPF_"开头
[reconnect] 认证失败后重连次数。参数为0时禁用重连功能。
```

参考文献
---------
iNode协议逆向研究初步入门by tsy http://www.cnblogs.com/bitpeach/p/4092806.html