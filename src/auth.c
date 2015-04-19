/*
 * Filename:     auth.c
 *
 * Created by:	 liuqun
 * Revised:      2015年4月19日
 * Revised by:   KiritoA
 * Description:  801.1X认证核心函数
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdbool.h>

#include <pcap.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#define sleep(x)	Sleep(x*1000)
#endif

#include "auth.h"
#include "md5.h"
#include "debug.h"
#include "adapter.h"

// 子函数声明
void HandleH3CRequest(int type, const uint8_t request[]);
static void SendStartPkt(pcap_t *adhandle, const uint8_t mac[], bool broadcast);
static void SendLogOffPkt(pcap_t *adhandle, const uint8_t mac[]);
static void SendResponseIdentity(pcap_t *adhandle, const uint8_t request[],
		const uint8_t ethhdr[], const uint8_t ip[4], const char username[],
		bool connected);
static void SendResponseMD5(pcap_t *adhandle, const uint8_t request[],
		const uint8_t ethhdr[], const char username[], const char passwd[]);
static void SendResponseSecurity(pcap_t *adhandle, const uint8_t request[],
		const uint8_t ethhdr[], const uint8_t ip[4], const char username[]);
static void SendResponseNotification(pcap_t *handle, const uint8_t request[],
		const uint8_t ethhdr[]);


static void FillZero(uint8_t *data, uint32_t len);
static void FillClientVersionArea(uint8_t area[]);
//static void FillWindowsVersionArea(uint8_t area[]);
static void FillBase64Area(char area[]);

void FillMD5Area(uint8_t digest[], uint8_t id, const char passwd[],
		const uint8_t srcMD5[]);


// typedef
typedef enum
{
	REQUEST = 1, RESPONSE = 2, SUCCESS = 3, FAILURE = 4, H3CDATA = 10
} EAP_Code;
typedef enum
{
	IDENTITY = 1, NOTIFICATION = 2, MD5_CHALLENGE = 4, SECURITY = 20
} EAP_Type;
typedef uint8_t EAP_ID;


const uint8_t BroadcastAddr[6] =
{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; // 广播MAC地址
const uint8_t MultcastAddr[6] =
{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 }; // 多播MAC地址
const char H3C_VERSION[16] = "EN\x11V7.00-0102"; // 华为客户端版本号
//const char H3C_KEY[64]    ="HuaWei3COM1X";  // H3C的固定密钥
const char H3C_KEY[64] = "Oly5D62FaE94W7"; // H3C的另一个固定密钥，网友取自MacOSX版本的iNode官方客户端

unsigned char pulse[32] =
{ 0x4b, 0x9d, 0xd2, 0xaf, 0xe6, 0xf7, 0x8a, 0xec, 0x6b, 0x97, 0x91, 0xf4, 0x62,
		0x32, 0x81, 0x49, 0x97, 0xb4, 0x26, 0x79, 0x2f, 0x16, 0x89, 0xfe, 0xc0,
		0x74, 0x3c, 0x4d, 0x4d, 0x43, 0x41, 0x02 };


/**
 * 函数：Authentication()
 *
 * 使用以太网进行802.1X认证(802.1X Authentication)
 * 该函数将不断循环，应答802.1X认证会话，直到遇到错误后才退出
 */

const int DefaultTimeout = 1500; //设置接收超时参数，单位ms
pcap_t *adhandle = NULL; // adapter handle
char errbuf[PCAP_ERRBUF_SIZE];
char FilterStr[100];
struct bpf_program fcode;

uint8_t ip[4] = { 0 };	// ip address
uint8_t MAC[6];
uint8_t ethhdr[14] = { 0 }; // ethernet header

/* 认证信息 */
const char *username = NULL;
const char *password = NULL;
const char *deviceName = NULL;

bool connected = false;

void InitDevice(const char *DeviceName)
{
	// NOTE: 这里没有检查网线是否已插好,网线插口可能接触不良

	/* 打开适配器(网卡) */
	adhandle = pcap_open_live(DeviceName, 65536, 1, DefaultTimeout, errbuf);
	if (adhandle == NULL)
	{
		fprintf(stderr, "%s\n", errbuf);
		exit(-1);
	}
	deviceName = DeviceName;
	/* 查询本机MAC地址 */
	GetMacFromDevice(MAC, DeviceName);

	/*
	 * 设置过滤器：
	 * 初始情况下只捕获发往本机的802.1X认证会话，不接收多播信息（避免误捕获其他客户端发出的多播信息）
	 * 进入循环体前可以重设过滤器，那时再开始接收多播信息
	 */
	sprintf(FilterStr,
			"(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",
			MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
	pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
	pcap_setfilter(adhandle, &fcode);
}

int Authentication(const char *UserName, const char *Password, const char *DeviceName)
{
	username = UserName;
 	password = Password;

	START_AUTHENTICATION:
	{
		int retcode;
		struct pcap_pkthdr *header = NULL;
		const uint8_t *captured = NULL;
		int retry=0;
		/* 主动发起认证会话 */
		SendStartPkt(adhandle, MAC, false);
		fprintf(stdout, "[INFO] C3H Client: Connecting to the network ...\n");

		/* 等待认证服务器的回应 */
		bool serverFound = false;
		while (!serverFound)
		{
			retcode = pcap_next_ex(adhandle, &header, &captured);
			if (retcode == 1 && (EAP_Code) captured[18] == REQUEST)
				serverFound = true;
			else
			{
				//重试达到最大次数后退出
				if(++retry == 5)
				{
					fprintf(stderr, "[ERROR] C3H Client: Server did not respond\n");
					return -1;
				}
				// 延时后重试
				sleep(2);
				DPRINTF(".");
				SendStartPkt(adhandle, MAC, false);
				// NOTE: 这里没有检查网线是否接触不良或已被拔下
			}
		}

		// 填写应答包的报头(以后无须再修改)
		// 默认以单播方式应答802.1X认证设备发来的Request
		memcpy(ethhdr + 0, captured + 6, 6);
		memcpy(ethhdr + 6, MAC, 6);
		ethhdr[12] = 0x88;
		ethhdr[13] = 0x8e;

		// 收到的第一个包可能是Request Notification。取决于校方网络配置
		if ((EAP_Type) captured[22] == NOTIFICATION)
		{
			fprintf(stdout,  "[INFO] C3H Client: Server responded\n");
			// 发送Response Notification
			SendResponseNotification(adhandle, captured, ethhdr);
			DPRINTF("[%d]H3C Client: Response Notification.\n", captured[19]);
			sleep(2);
			// 继续接收下一个Request包
			retcode = pcap_next_ex(adhandle, &header, &captured);
			assert(retcode == 1);
			assert((EAP_Code )captured[18] == REQUEST);
		}

		// 分情况应答下一个包
		if ((EAP_Type) captured[22] == IDENTITY)
		{
			// 通常情况会收到包Request Identity，应回答Response Identity
			fprintf(stdout, "[INFO] C3H Client: Beginning authentication\n");
			GetIpFromDevice(ip, DeviceName);
			SendResponseIdentity(adhandle, captured, ethhdr, ip, UserName, false);
			DPRINTF("[%d]Client: Response Identity.\n", (EAP_ID )captured[19]);
		}
		else if ((EAP_Type)captured[22] == SECURITY)
		{	// 遇到AVAILABLE包时需要特殊处理
			// 中南财经政法大学目前使用的格式：
			// 收到第一个Request AVAILABLE时要回答Response Identity
			fprintf(stdout, "[%d]C3H Client: Beginning authentication\n", captured[19]);
			GetIpFromDevice(ip, DeviceName);
			SendResponseIdentity(adhandle, captured, ethhdr, ip, UserName, false);
			DPRINTF("[%d]Client: Response Identity.\n", (EAP_ID)captured[19]);
		}

		// 重设过滤器，只捕获华为802.1X认证设备发来的包（包括多播Request Identity / Request AVAILABLE）
		sprintf(FilterStr,
				"(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x)",
				captured[6], captured[7], captured[8], captured[9],
				captured[10], captured[11]);
		pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
		pcap_setfilter(adhandle, &fcode);
		
		// 进入循环体
		for (;;)
		{
			// 调用pcap_next_ex()函数捕获数据包
			while (pcap_next_ex(adhandle, &header, &captured) != 1)
			{
				//DPRINTF("."); // 若捕获失败，则等1秒后重试
				//sleep(1);     // 直到成功捕获到一个数据包后再跳出
				// NOTE: 这里没有检查网线是否已被拔下或插口接触不良
			}

			// 根据收到的Request，回复相应的Response包
			if ((EAP_Code) captured[18] == REQUEST)
			{
				HandleH3CRequest(captured[22], captured);
			}
			else if ((EAP_Code) captured[18] == FAILURE)
			{
				connected = false;
				// 处理认证失败信息
				uint8_t errtype = captured[22];
				uint8_t msgsize = captured[23];
				const char *msg = (const char*) &captured[24];
				fprintf(stderr, "[ERROR] C3H Client: Failure.\n");
				if (errtype == 0x09 && msgsize > 0)
				{	// 输出错误提示消息
					fprintf(stderr, "%s\n", msg);
					// 已知的几种错误如下
					// E2531:用户名不存在
					// E2535:Service is paused
					// E2542:该用户帐号已经在别处登录
					// E2547:接入时段限制
					// E2553:密码错误
					// E2602:认证会话不存在
					// E3137:客户端版本号无效
					exit(-1);
				}
				else if (errtype == 0x08) // 可能网络无流量时服务器结束此次802.1X认证会话
				{	// 遇此情况客户端立刻发起新的认证会话
					goto START_AUTHENTICATION;
				}
				else
				{
					DPRINTF("errtype=0x%02x\n", errtype);
					exit(-1);
				}
			}
			else if ((EAP_Code) captured[18] == SUCCESS)
			{
				connected = true;
				fprintf(stdout, "[INFO] C3H Client: You have passed the identity authentication\n");
				// 刷新IP地址
				fprintf(stdout, "[INFO] C3H Client: Obtaining IP address...\n");
				RefreshIPAddress();
				//GetIpFromDevice(ip, DeviceName);
				//fprintf(stdout, "[INFO] C3H Client: Current IP address is %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
			}
			else if ((EAP_Code)captured[18] == H3CDATA)
			{
				fprintf(stdout, "[%d] Server: (H3C data)\n", captured[19]);
				// TODO: 需要解出华为自定义数据包内容，该部分内容与心跳包数据有关
			}
			else
			{
				DPRINTF("[%d] H3C:Unknown Code:%d\n", captured[18]);
			}
		}
	}
	return (0);
}

void LogOff()
{
	if(connected)
	{
		SendLogOffPkt(adhandle, MAC);

		fprintf(stdout, "\n[INFO] C3H Client: Log off. \n");
	}
	else
	{
		fprintf(stdout, "\n[INFO] C3H Client: Cancel. \n");
	}
}

void HandleH3CRequest(int type, const uint8_t request[])
{
	switch (type)
	{
	case IDENTITY:
		if (connected)
		{
			DPRINTF("[%d] Server: Request Identity!\n",
					(EAP_ID )captured[19]);
			GetIpFromDevice(ip, deviceName);
			SendResponseIdentity(adhandle, request, ethhdr, ip, username,
					connected);

			DPRINTF("[%d] Client: Response Identity*\n",
					(EAP_ID )captured[19]);
		}
		else
		{
			DPRINTF("[%d] Server: Request Identity!\n",
					(EAP_ID )captured[19]);
			GetIpFromDevice(ip, deviceName);
			SendResponseIdentity(adhandle, request, ethhdr, ip, username,
					connected);
			DPRINTF("[%d] Client: Response Identity.\n",
					(EAP_ID )captured[19]);
		}
		break;
	case SECURITY:
		DPRINTF("[%d] Server: Request SECURITY!\n",
				(EAP_ID )captured[19]);
		GetIpFromDevice(ip, deviceName);

		SendResponseSecurity(adhandle, request, ethhdr, ip, username);

		DPRINTF("[%d] Client: Response SECURITY.\n",
				(EAP_ID )captured[19]);
		break;
	case MD5_CHALLENGE:
		DPRINTF("[%d] Server: Request MD5-Challenge!\n",
				(EAP_ID )captured[19]);
		SendResponseMD5(adhandle, request, ethhdr, username, password);
		DPRINTF("[%d] Client: Response MD5-Challenge.\n",
				(EAP_ID )captured[19]);
		break;
	case NOTIFICATION:
		DPRINTF("[%d] Server: Request Notification!\n",
				captured[19]);
		SendResponseNotification(adhandle, request, ethhdr);
		DPRINTF("     Client: Response Notification.\n");
		break;
	default:
		DPRINTF("[%d] Server: Request (type:%d)!\n",
				(EAP_ID )captured[19], (EAP_Type )captured[22]);
		DPRINTF("Error! Unexpected request type\n");
		exit(-1);
		break;
	}
}

static void SendStartPkt(pcap_t *handle, const uint8_t localmac[],
bool broadcast)
{
	uint8_t packet[18];

	if (broadcast)
	{
		// 1、广播发送Strat包
		memcpy(packet, BroadcastAddr, 6);
	}
	else
	{
		// 2、多播发送Strat包
		memcpy(packet, MultcastAddr, 6);
	}
	// Ethernet Header (14 Bytes)
	//
	memcpy(packet + 6, localmac, 6);
	packet[12] = 0x88;
	packet[13] = 0x8e;

	// EAPOL (4 Bytes)
	packet[14] = 0x01;	// Version=1
	packet[15] = 0x01;	// Type=Start
	packet[16] = packet[17] = 0x00;	// Length=0x0000

	pcap_sendpacket(handle, packet, sizeof(packet));
}

static
void SendLogOffPkt(pcap_t *handle, const uint8_t localmac[])
{
	uint8_t packet[18];

	// Fill Ethernet header
	memcpy(packet, ethhdr, 14);

	// EAPOL (4 Bytes)
	packet[14] = 0x01;	// Version=1
	packet[15] = 0x02;	// Type=Logoff
	packet[16] = packet[17] = 0x00;	// Length=0x0000

	// 发包
	pcap_sendpacket(handle, packet, sizeof(packet));
}

static
void SendResponseNotification(pcap_t *handle, const uint8_t request[],
		const uint8_t ethhdr[])
{
	uint8_t response[60];
	assert((EAP_Code )request[18] == REQUEST);
	assert((EAP_Type )request[22] == NOTIFICATION);

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
	response[14] = 0x1;	// 802.1X Version 1
	response[15] = 0x0;	// Type=0 (EAP Packet)
	response[16] = 0x00;	// Length
	response[17] = 0x1b;	//2015.4.13 佛大客户端修订

		// Extensible Authentication Protocol
		// {
		response[18] = (EAP_Code) RESPONSE;	// Code
		response[19] = (EAP_ID) request[19];	// ID
		response[20] = response[16];		// Length
		response[21] = response[17];		//
		response[22] = (EAP_Type) NOTIFICATION;	// Type

		int i = 23;
		/* Notification Data (44 Bytes) */
		// 其中前2+20字节为客户端版本
		response[i++] = 0x01; // type 0x01
		response[i++] = 22;   // lenth
		FillClientVersionArea(response + i);
		i += 20;

		//2015.4.13 佛大客户端修订,不需要系统版本号，最后15字节为0x00
		FillZero(response+i, 15);
		i += 15;

		//最后2+20字节存储加密后的Windows操作系统版本号
		/*
		 response[i++] = 0x02; // type 0x02
		 response[i++] = 22;   // length
		 FillWindowsVersionArea(response+i);
		 i += 20;*/
		// }
	// }
	pcap_sendpacket(handle, response, sizeof(response));
}


static
void SendResponseSecurity(pcap_t *handle, const uint8_t request[],
		const uint8_t ethhdr[], const uint8_t ip[4], const char username[])
{
	int i;
	uint16_t eaplen;
	int usernamelen;
	uint8_t response[128];

	assert((EAP_Code )request[18] == REQUEST);
	assert((EAP_Type )request[22] == SECURITY);

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
	response[14] = 0x01;	// 802.1X Version 1
	response[15] = 0x00;	// Type=0 (EAP Packet)
	//response[16~17]留空	// Length

		// Extensible Authentication Protocol
		// {
		response[18] = (EAP_Code) RESPONSE;	// Code
		response[19] = request[19];		// ID
		//response[20~21]留空			// Length
		
		response[22] = (EAP_Type) SECURITY;	// Type
			// Type-Data
			// {
			i = 23;

			//response[i++] = 0x00;	// 上报是否使用代理，取消此处注释会导致马上断线拉黑
			//暂时未能解密该部分内容，只作填充0处理
			response[i++] = 0x16;
			response[i++] = 0x20;	//Length
			//memcpy(response + i, pulse, 32);
			FillZero(response+i, 15);
			i += 32;
				
			response[i++] = 0x15;	  // 上传IP地址
			response[i++] = 0x04;	  //
			memcpy(response + i, ip, 4);	  //
			i += 4;			  //
			response[i++] = 0x06;		  // 携带版本号
			response[i++] = 0x07;		  //
			FillBase64Area((char*) response + i);		  //
			i += 28;			  //
			response[i++] = ' '; // 两个空格符
			response[i++] = ' '; //
			usernamelen = strlen(username);
			memcpy(response + i, username, usernamelen); //
			i += usernamelen;			  //
			// }
		// }
	// }

	// 补填前面留空的两处Length
	eaplen = htons(i - 18);
	memcpy(response + 16, &eaplen, sizeof(eaplen));
	memcpy(response + 20, &eaplen, sizeof(eaplen));

	// 发送
	pcap_sendpacket(handle, response, i);
}

static
void SendResponseIdentity(pcap_t *adhandle, const uint8_t request[],
		const uint8_t ethhdr[], const uint8_t ip[4], const char username[],
		bool connected)
{
	uint8_t response[128];
	size_t i;
	uint16_t eaplen;
	int usernamelen;

	assert((EAP_Code )request[18] == REQUEST);
	assert((EAP_Type )request[22] == IDENTITY);

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
	response[14] = 0x01;	// 802.1X Version 1
	response[15] = 0x00;	// Type=0 (EAP Packet)
	//response[16~17]留空	// Length

		// Extensible Authentication Protocol
		// {
		response[18] = (EAP_Code) RESPONSE;	// Code
		response[19] = request[19];		// ID
		//response[20~21]留空			// Length
		response[22] = (EAP_Type) IDENTITY;	// Type
			// Type-Data
			// {
			i = 23;
			if(connected)
			{
				//连接后需要上报的内容
				//暂时未能解密该部分内容，只作填充0处理
				response[i++] = 0x16;
				response[i++] = 0x20;	//Length
				//memcpy(response + i, pulse, 32);
				FillZero(response+i, 15);
				i += 32;
				
				response[i++] = 0x15;	  // 上传IP地址
				response[i++] = 0x04;	  //
				memcpy(response+i, ip, 4);//
				i += 4;
			}

			response[i++] = 0x06;		  // 携带版本号
			response[i++] = 0x07;		  //
			FillBase64Area((char*) response + i);		  //
			i += 28;			  //
			response[i++] = ' '; // 两个空格符
			response[i++] = ' '; //
			usernamelen = strlen(username); //末尾添加用户名
			memcpy(response + i, username, usernamelen);
			i += usernamelen;
			assert(i <= sizeof(response));
			// }
		// }
	// }

	// 补填前面留空的两处Length
	eaplen = htons(i - 18);
	memcpy(response + 16, &eaplen, sizeof(eaplen));
	memcpy(response + 20, &eaplen, sizeof(eaplen));

	// 发送
	pcap_sendpacket(adhandle, response, i);
	return;
}

static
void SendResponseMD5(pcap_t *handle, const uint8_t request[],
		const uint8_t ethhdr[], const char username[], const char passwd[])
{
	uint16_t eaplen;
	size_t usernamelen;
	size_t packetlen;
	uint8_t response[128];

	assert((EAP_Code )request[18] == REQUEST);
	assert((EAP_Type )request[22] == MD5_CHALLENGE);

	usernamelen = strlen(username);
	eaplen = htons(22 + usernamelen);
	packetlen = 14 + 4 + 22 + usernamelen; // ethhdr+EAPOL+EAP+usernamelen

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
	response[14] = 0x01;	// 802.1X Version 1
	response[15] = 0x00;	// Type=0 (EAP Packet)
	memcpy(response + 16, &eaplen, sizeof(eaplen));	// Length

		// Extensible Authentication Protocol
		// {
		response[18] = (EAP_Code) RESPONSE;		// Code
		response[19] = request[19];	// ID
		response[20] = response[16];	// Length
		response[21] = response[17];	//
		response[22] = (EAP_Type) MD5_CHALLENGE;	// Type
		response[23] = 16;		// Value-Size: 16 Bytes
		FillMD5Area(response + 24, request[19], passwd, request + 24);
		memcpy(response + 40, username, usernamelen);
		// }
	// }

	pcap_sendpacket(handle, response, packetlen);
}

// 函数: XOR(data[], datalen, key[], keylen)
//
// 使用密钥key[]对数据data[]进行异或加密
//（注：该函数也可反向用于解密）
static
void XOR(uint8_t data[], unsigned dlen, const char key[], unsigned klen)
{
	unsigned int i, j;

	// 先按正序处理一遍
	for (i = 0; i < dlen; i++)
		data[i] ^= key[i % klen];
	// 再按倒序处理第二遍
	for (i = dlen - 1, j = 0; j < dlen; i--, j++)
		data[i] ^= key[j % klen];
}

static
void FillClientVersionArea(uint8_t area[20])
{
	uint32_t random;
	char RandomKey[8 + 1];

	random = (uint32_t) time(NULL);    // 注：可以选任意32位整数
	sprintf(RandomKey, "%08x", random);    // 生成RandomKey[]字符串

	// 第一轮异或运算，以RandomKey为密钥加密16字节
	memcpy(area, H3C_VERSION, sizeof(H3C_VERSION));
	XOR(area, 16, RandomKey, strlen(RandomKey));

	// 此16字节加上4字节的random，组成总计20字节
	random = htonl(random); // （需调整为网络字节序）
	memcpy(area + 16, &random, 4);

	// 第二轮异或运算，以H3C_KEY为密钥加密前面生成的20字节
	XOR(area, 20, H3C_KEY, strlen(H3C_KEY));
}

static
void FillZero(uint8_t *data, uint32_t len)
{
	while(len--)
	{
		*data = 0x00;
	}
}

/*
static
void FillWindowsVersionArea(uint8_t area[20])
{
	const uint8_t WinVersion[20] = "r70393861";

	memcpy(area, WinVersion, 20);
	XOR(area, 20, H3C_KEY, strlen(H3C_KEY));
}*/

static
void FillBase64Area(char area[])
{
	uint8_t version[20];
	const char Tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz"
			"0123456789+/"; // 标准的Base64字符映射表
	uint8_t c1, c2, c3;
	int i, j;

	// 首先生成20字节加密过的H3C版本号信息
	FillClientVersionArea(version);

	// 然后按照Base64编码法将前面生成的20字节数据转换为28字节ASCII字符
	i = 0;
	j = 0;
	while (j < 24)
	{
		c1 = version[i++];
		c2 = version[i++];
		c3 = version[i++];
		area[j++] = Tbl[(c1 & 0xfc) >> 2];
		area[j++] = Tbl[((c1 & 0x03) << 4) | ((c2 & 0xf0) >> 4)];
		area[j++] = Tbl[((c2 & 0x0f) << 2) | ((c3 & 0xc0) >> 6)];
		area[j++] = Tbl[c3 & 0x3f];
	}
	c1 = version[i++];
	c2 = version[i++];
	area[24] = Tbl[(c1 & 0xfc) >> 2];
	area[25] = Tbl[((c1 & 0x03) << 4) | ((c2 & 0xf0) >> 4)];
	area[26] = Tbl[((c2 & 0x0f) << 2)];
	area[27] = '=';
}


void FillMD5Area(uint8_t digest[], uint8_t id, const char passwd[], const uint8_t srcMD5[])
{
	uint8_t	msgbuf[128]; // msgbuf = ‘id‘ + ‘passwd’ + ‘srcMD5’
	size_t	msglen;
	size_t	passlen;

	passlen = strlen(passwd);
	msglen = 1 + passlen + 16;
	assert(sizeof(msgbuf) >= msglen);

	msgbuf[0] = id;
	memcpy(msgbuf+1,	 passwd, passlen);
	memcpy(msgbuf+1+passlen, srcMD5, 16);

	md5_state_t state;
	md5_init(&state);
	md5_append(&state, (const md5_byte_t *)msgbuf, msglen);
	md5_finish(&state, digest);
}
