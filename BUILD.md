# BUILD

> 使用OpenWRT SDK编译适用于路由器的ipk文件过程<br>
> 我使用的编译环境：Ubuntu 15.10 x64


## 环境搭建

### 安装编译环境所需的依赖
```
sudo apt-get install libncurses5-dev zlib1g-dev gawk flex patch git-core g++ subversion libpcap-dev libssl-dev
```
### 下载SDK
在 [OpenWRT下载页](http://downloads.openwrt.org/) 下载适配于你的路由器固件版本及型号的SDK，比如我使用的Newifi Y1(mt7620a芯片) + PandoraBox 14.09固件，则下载
```
http://downloads.openwrt.org/barrier_breaker/14.07/ramips/mt7620a/OpenWrt-SDK-ramips-for-linux-x86_64-gcc-4.8-linaro_uClibc-0.9.33.2.tar.bz2
```
解压SDK

## 编译
### 部署源码
将本项目源代码下载后放到 SDK 中的`package`目录下，最终目录结构为：
```
package
├── c3h-client
│   ├── Makefile
│   └── src
│       ├── adapter.c
│       ├── adapter.h
│       ├── auth.c
│       ├── auth.h
│       ├── defs.h
│       ├── main.c
│       ├── Makefile
│       ├── md5.c
│       └── md5.h
└── Makefile
```
此时共有三个Makefile文件，其中package中的Makefile为SDK自带，不需要改动，将c3h-client文件夹直接置入package文件夹中即可

### 配置编译变量
在SDK的根目录中执行
``` bash
make menuconfig
```
![Alt text](https://github.com/mcdona1d/ImageCache/raw/master/c3h-client/1454035791140.png)
c3h-client放置正确则会出现Network选项，进入Network选项，摁M确定编译ipk文件（默认可能已经就是M）如图：
![Alt text](https://github.com/mcdona1d/ImageCache/raw/master/c3h-client/1454035864792.png)
选择SAVE，OK。随后EXIT即可完成编译配置

### 正式编译

在SDK根目录执行`make`命令，
![Alt text](https://github.com/mcdona1d/ImageCache/raw/master/c3h-client/1454035986275.png)
如果没有报错信息出现，则编译成功，编译成功的ipk会出现在SDK目录下的bin目录中，根据你的SDK不同路径也会略有不同，比如我的文件在
``` bash
./bin/ramips/packages/base/c3h-client_1.0.0-1_ramips_24kec.ipk
```

如果编译出现错误，则需要使用如下命令定位错误原因
```
make -j1 V=s
（使用单核心编译，输出编译信息）
```
## 安装

### 配置系统兼容性

对于ramips芯片的机器，比如我的Newifi Y1和HG255d，安装前需要先将以下四行添加到`/etc/opkg.conf`中，否则会出现`Unknown package 'c3h-client'`的兼容性问题
```
arch all 100  
arch ralink 200  
arch ramips 300  
arch ramips_24kec 400  
```

### 正式安装

本程序在我所使用的PandoraBox 基于14.09源码的固件中，需要依赖1.5.3-1版本的libpcap：`libpcap_1.5.3-1_ramips_24kec.ipk`
此文件可以在与SDK下载路径相同的目录中的`packages/base/`中下载到，比如我所使用的mt7620a芯片所适用的
```
http://downloads.openwrt.org/barrier_breaker/14.07/ramips/mt7620a/packages/base/libpcap_1.5.3-1_ramips_24kec.ipk
```
经测试使用路由器自带的软件包安装所得的`libpcap_1.7.4-1_ramips_24kec.ipk`并**不能支持**`h3c-client`运行

安装时需要先安装`libpcap`随后安装`c3h-client`
安装过程及截图如下图所示
![Alt text](https://github.com/mcdona1d/ImageCache/raw/master/c3h-client/1454036761908.png)

如果能正常输出Usage信息及Adapters available可以列出当前可用网卡，则安装成功


## Q&A
Q : 执行`c3h-client`报错`c3h-client: can't load library 'libc.so'`<br>
A : 安装了1.7.4版本的libpcap，版本过高，请使用1.5.3版本

Q : 执行`c3h-client`报错`c3h-client: can't load library 'libpcap.so.1.3'`<br>
A : 安装了1.1.1版本的libpcap，版本过低，请使用1.5.3版本