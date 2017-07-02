c3h-client(0-day edition)
===========

> **当前分支为 0-day 版，如果需要普通版（旧版），请切换至 `normal` 分支**  
>
> **0-day 版已稳定连续运行两年*

该项目代码源于以下项目：

njit8021xclient:https://github.com/liuqun/njit8021xclient

以及bitdust的fork:https://github.com/bitdust/njit8021xclient

由于项目根据njit8021xclient重构了大部分程序代码，因此决定从该项目分离并建立一个新项目

**本项目仅作为 H3C iNode 在 Linux 平台下的解决方案，如果你需要天翼校园客户端在 Linux 平台下的解决方案，请移步：https://github.com/YianAndCode/f-surfing*

License
---------
本项目继承并遵循GPLv3协议

概述
-----
* 本项目重构了njit8021xclient大部分代码，优化程序框架结构，增强可读性
* 本项目利用了 H3C 认证的 0-day 漏洞（由 [@KiritoA](https://github.com/KiritoA) 及其舍友在无意中发现），可以解决部分高校出现 `0x0A` 失败的情况，以及可以实现不被服务端拉黑
* 测试版本：iNode V7.00-0102
* 测试环境为佛大
* 模仿官方客户端响应EAP报文的程序逻辑
* 可跨平台运作于Linux/openWRT/Windows
* 集成MD5算法，不需要依赖openssl
* 增加断线重连机制
* 集成makefile(BETA)

## 0-day 版原理

在收到 `SECURITY `类型的请求后，首先给服务器一个无效 `SECURITY` 回应，然后立即重新发起认证（EAPOL，Start），之后服务器按正常流程会请求`Identify`，此时开始回应头部正确，内容无效的报文，服务器由于一直未收到正确回应报文，会再次请求 `Identify`，同样回应无效报文，如此循环就可以不掉线且不被拉黑

依赖的开发包
--------
* Linux/openWRT: libpcap
* Windows: WinPcap(WpdPack)

## 编译

Linux 平台下可以直接在 `src/` 目录下执行 `make` 进行编译；

OpenWrt 可以使用由 [@mcdona1d](https://github.com/mcdona1d/c3h-client) 修改的 `makefile` 进行交叉编译

研究进度
-----
佛大校园网测试可成功认证，但交换机启用了客户端程序完整性检测机制（响应报文为`SendResponseSecurity()`函数），导致认证成功后一段时间会强制下线，并将用户拉入黑名单。按照目前网络上已有研究，解决该问题需要对客户端程序反编译后提取所需数据并上传。
参考https://github.com/bitdust/njit8021xclient/blob/master/documents/h3c_AES_MD5.md

在auth.c中`SendResponseSecurity()`函数中
```
response[i++] = 0x00;	// 上报是否使用代理
```
此行代码取消注释后，不会立即强制下线，但7分钟后仍会断开（服务器收不到正确报文而强制下线），重新连接不会被拉黑。

2015.12.23：据反映部分宿舍楼可以使用此客户端而不会加入黑名单。

用法
-----
```
c3h-client  [username] [password] [adapter] [reconnect]

[Username]	用户名
[password]	密码
[adapter]	认证网卡。
			Linux中网卡为eth0,eth1...
			Windows中网卡以"\Device\NPF_"开头
[reconnect]	认证失败或被踢下线后重连次数。参数为0时禁用重连功能。
```

参考文献
---------
iNode协议逆向研究初步入门by tsy http://www.cnblogs.com/bitpeach/p/4092806.html
