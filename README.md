c3h-client
===========
该项目代码源于以下项目：

njit8021xclient:https://github.com/liuqun/njit8021xclient

以及bitdust的fork:https://github.com/bitdust/njit8021xclient


由于对njit8021xclient版本的结构和内容作出不少修改，因此决定从该项目分离并建立一个新项目


概述
-----
* 基于iNode V7.00-0102版本的网络数据包分析进行修改
* 可运作于Linux/openWRT/Windows
* 集成MD5算法，不需要再依赖openssl
* 测试环境为佛大

依赖的开发包
--------
* Linux/openWRT: libpcap
* Windows: WinPcap(WpdPack)

测试日志
-----
* 2015-4-19：佛大校园网可成功认证，但校园网在心跳包加入了检测，目前每7分钟会断线一次，之后可重新连接不会被拉黑

用法
-----
Linux/openWRT
```
c3h-client  [username]  [password]
c3h-client  [username]  [password]  eth0
c3h-client  [username]  [password]  eth1
```
Windows
```
c3h-client  [username]  [password]	[adapter]
```

参考文献
---------
iNode协议逆向研究初步入门by tsy http://www.cnblogs.com/bitpeach/p/4092806.html