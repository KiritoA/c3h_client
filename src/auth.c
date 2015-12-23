/*
 * Filename:     auth.c
 *
 * Created by:	 liuqun
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

#endif

#include "auth.h"
#include "md5.h"
#include "defs.h"
#include "adapter.h"

// 子函数声明
static void HandleEAPRequest(int type, const uint8_t request[]);

static void SendEAPOL(uint8_t type);
static void SendEAPPacket(uint8_t code, uint8_t type, uint8_t id, uint8_t *extPkt, uint16_t extLen);

static void SendStartPkt();
static void SendLogOffPkt();
static void SendResponseIdentity(const uint8_t request[]);
static void SendResponseMD5(const uint8_t request[]);
static void SendResponseSecurity(const uint8_t request[]);
static void SendResponseNotification(const uint8_t request[]);

static void FillClientVersionArea(uint8_t area[]);
//static void FillWindowsVersionArea(uint8_t area[]);
static void FillBase64Area(char area[]);
static void FillMD5Area(uint8_t digest[], uint8_t id, const char passwd[],
		const uint8_t srcMD5[]);

int got_packet(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet);

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

const int DefaultTimeout = 1500; //设置接收超时参数，单位ms

uint8_t local_ip[4] = { 0, 0, 0, 0 };	// ip address
uint8_t local_mac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

uint8_t AES_MD5req[32];
uint8_t AES_MD5rsp[32];

eth_header_t eth_header; // ethernet header

/* 认证信息 */
const char *username = NULL;
const char *password = NULL;
const char *deviceName = NULL;

/* pcap */
pcap_t *adhandle = NULL; // adapter handle

int authProgress = AUTH_PROGRESS_DISCONNECT;
bool success = false;//认证成功标志位

void InitDevice(const char *DeviceName)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	/* 打开适配器(网卡) */
	adhandle = pcap_open_live(DeviceName, 65536, 1, DefaultTimeout, errbuf);
	if (adhandle == NULL)
	{
		PRINTERR("%s\n", errbuf);
		exit(-1);
	}
	deviceName = DeviceName;
	/* 查询本机MAC地址 */
	GetMacFromDevice(local_mac, deviceName);
}

void CloseDevice()
{
	if (adhandle != NULL)
	{
		pcap_close(adhandle);
		adhandle = NULL;
	}
}


/**
 * 函数：Authentication()
 *
 * 使用以太网进行802.1X认证(802.1X Authentication)
 * 该函数将不断循环，应答802.1X认证会话，直到遇到错误后才退出
 */
int Authentication(const char *UserName, const char *Password)
{
	struct pcap_pkthdr *header = NULL;
	char FilterStr[100];
	struct bpf_program fcode;

	username = UserName;
 	password = Password;

	authProgress = AUTH_PROGRESS_START;

	success = false;
	/*
	* 设置过滤器：
	* 初始情况下只捕获发往本机的802.1X认证会话，不接收多播信息（避免误捕获其他客户端发出的多播信息）
	* 进入循环体前可以重设过滤器，那时再开始接收多播信息
	*/
	sprintf(FilterStr,
		"(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",
		local_mac[0], local_mac[1], local_mac[2], local_mac[3], local_mac[4], local_mac[5]);
	pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
	pcap_setfilter(adhandle, &fcode);

	// 初始化应答包的报头
	// 默认以多播方式应答802.1X认证设备发来的Request
	memcpy(eth_header.dest_mac, MultcastAddr, 6);
	memcpy(eth_header.src_mac, local_mac, 6);
	eth_header.eth_type = htons(0x888e);	//88 8e

	/* 主动发起认证会话 */
	SendStartPkt();
	PRINTMSG( "C3H Client: Connecting to the network ...");

	int retcode = 0;
	int retry = 0;

	const u_char *captured = NULL;

	/* 等待认证服务器的回应 */
	bool serverFound = false;
	while (!serverFound)
	{
		retcode = pcap_next_ex(adhandle, &header, &captured);
		if (retcode == 1 && (EAP_Code)captured[18] == REQUEST)
		{
			serverFound = true;
			PRINT("\n");
			PRINTMSG("C3H Client: Server responded\n");
		}
		else
		{
			//重试达到最大次数后退出
			if (retry++ == 5)
			{
				PRINT("\n");
				PRINTERR("C3H Client[ERROR]: Server did not respond\n");
				return ERR_NOT_RESPOND;
			}
			// 延时后重试
			sleep(3);
			PRINT(".");
			SendStartPkt();
			// NOTE: 这里没有检查网线是否接触不良或已被拔下
		}
	}

	//收到报文后修改为单播地址认证
	memcpy(eth_header.dest_mac, captured + 6, 6);

	// 重设过滤器，只捕获华为802.1X认证设备发来的包（包括多播Request Identity / Request AVAILABLE）
	sprintf(FilterStr,
			"(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x)",
			captured[6], captured[7], captured[8], captured[9],
			captured[10], captured[11]);
	pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
	pcap_setfilter(adhandle, &fcode);

	if ((retcode = got_packet(NULL, header, captured)) != 0)
		return retcode;

	// 进入循环体
	for (;;)
	{
		// 调用pcap_next_ex()函数捕获数据包
		if (pcap_next_ex(adhandle, &header, &captured) == 1)
		{
			if ((retcode = got_packet(NULL, header, captured)) != 0)
				break;
		}
			
	}

	authProgress = AUTH_PROGRESS_DISCONNECT;
	return (retcode);
}

void LogOff()
{
	if (authProgress == AUTH_PROGRESS_CONNECTED)
	{
		PRINTMSG( "C3H Client: Log off.\n");
	}
	else
	{
		PRINTMSG( "C3H Client: Cancel.\n");
	}

	SendLogOffPkt(adhandle, local_mac);
	authProgress = AUTH_PROGRESS_DISCONNECT;
}

int got_packet(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet)
{
	int retcode = 0;
	int i;
	const eap_header_t *eapHeader = (eap_header_t*)(packet + ETH_LEN);

	uint8_t errtype = packet[22];
	uint8_t msgsize = packet[23];
	const char *msg = (const char*)&packet[24];

	switch (eapHeader->code)
	{
	case REQUEST:
		// 根据收到的Request，回复相应的Response包
		HandleEAPRequest(eapHeader->type, packet);
		break;
	case SUCCESS:
		if (authProgress == AUTH_PROGRESS_INENTITY || authProgress == AUTH_PROGRESS_PASSWORD)
		{
			authProgress = AUTH_PROGRESS_CONNECTED;
			success = true;

			PRINTMSG("C3H Client: You have passed the identity authentication\n");
			// 刷新IP地址
			PRINTMSG("C3H Client: Obtaining IP address...\n");
			RefreshIPAddress();
			//GetIpFromDevice(local_ip, deviceName);
			//PRINTMSG("C3H Client: Current IP address is %d.%d.%d.%d\n", local_ip[0], local_ip[1], local_ip[2], local_ip[3]);
		}
		break;
	case FAILURE:
		authProgress = AUTH_PROGRESS_DISCONNECT;
		// 处理认证失败信息
		
		if (errtype == 0x09 && msgsize > 0)
		{
			char* errMsg = (char*)malloc(msgsize + 2);
			strncpy(errMsg, msg, msgsize);
			errMsg[msgsize] = '\n';
			errMsg[msgsize+1] = '\0';
			PRINTERR(errMsg);
			free(errMsg);
			// 已知的几种错误如下
			// E63100:客户端版本号无效
			// E63013:用户被列入黑名单
			// E63015:用户已过期
			// E63027:接入时段限制

			if (strncmp(msg, "E63100", 6) == 0)
				return ERR_AUTH_INVALID_VERSION;
			else if (strncmp(msg, "E63027", 6) == 0)
				return ERR_AUTH_TIME_LIMIT;
			else if (strncmp(msg, "E63025", 6) == 0)
				return ERR_AUTH_MAC_FAILED;
			else
				return ERR_AUTH_FAILED;
		}
		else
		{
			PRINTERR("C3H Client[ERROR]: Unexpected failure(Code:0x%02x)\n", errtype);
			if (success)
				//若为连接成功后断线，返回另一个标志
				return ERR_FAILED_AFTER_SUCCESS;
			else
				return ERR_UNKNOWN_FAILED;
		}

		break;
	case H3CDATA:
		PRINTMSG("[%d] Server: (H3C data)\n", eapHeader->id);
		// TODO: 需要解出华为自定义数据包内容，该部分内容与心跳包数据有关

		if (packet[26] == 0x35)
		{
			for ( i = 0; i < 32; i++)
			{
				AES_MD5req[i] = packet[i + 27];
			}
			//h3c_AES_MD5_decryption(AES_MD5data, AES_MD5req);
		}
		break;
	default:
		break;
	}

	return retcode;
}

static void HandleEAPRequest(int type, const uint8_t request[])
{
	switch (type)
	{
	case IDENTITY:
		PRINTDEBUG("[%d] Server: Request Identity!\n", (EAP_ID)request[19]);
		if (authProgress == AUTH_PROGRESS_START)
		{
			authProgress = AUTH_PROGRESS_INENTITY;
			PRINTMSG("C3H Client: Beginning authentication... [%s]\n", username);
		}

		if (authProgress == AUTH_PROGRESS_INENTITY || authProgress == AUTH_PROGRESS_CONNECTED)
		{
			SendResponseIdentity(request);
			PRINTDEBUG("[%d] Client: Response Identity.\n", (EAP_ID)request[19]);
		}
		break;
	case SECURITY:
		PRINTDEBUG("[%d] Server: Request Security!\n", (EAP_ID)request[19]);
		if (authProgress == AUTH_PROGRESS_START)
		{
			authProgress = AUTH_PROGRESS_INENTITY;
			PRINTMSG("C3H Client: Beginning authentication... [%s]\n", username);
		}
		if (authProgress == AUTH_PROGRESS_INENTITY)
			SendResponseIdentity(request);
		else if (authProgress == AUTH_PROGRESS_CONNECTED)
		{
			SendResponseSecurity(request);
			PRINTDEBUG("[%d] Client: Response Security.\n", (EAP_ID)request[19]);
		}

		break;
	case MD5_CHALLENGE:
		PRINTDEBUG("[%d] Server: Request MD5-Challenge!\n", (EAP_ID)request[19]);
		if (authProgress == AUTH_PROGRESS_INENTITY)
		{
			authProgress = AUTH_PROGRESS_PASSWORD;
			PRINTMSG("C3H Client: Authenticating password...\n");
		}
		if (authProgress >= AUTH_PROGRESS_PASSWORD)
		{
			SendResponseMD5(request);
			PRINTDEBUG("[%d] Client: Response MD5-Challenge.\n",
				(EAP_ID)request[19]);
		}
		break;
	case NOTIFICATION:
		PRINTDEBUG("[%d] Server: Request Notification!\n", request[19]);
		// 发送Response Notification
		SendResponseNotification(request);
		PRINTDEBUG("[%d] Client: Response Notification.\n", request[19]);
		break;
	default:
		break;
	}
}

static void SendEAPPacket(uint8_t code, uint8_t type, uint8_t id, uint8_t *extPkt, uint16_t extLen)
{
	uint8_t packet[120];
	size_t i = 0;
	eap_header_t eap_header; // eap header

	// Fill Ethernet header
	memcpy(packet, &eth_header, ETH_LEN);
	i += ETH_LEN;
	// 802.1X Authentication
	eap_header.header.type = 0x00;	//Type: EAP Packet (0)
	eap_header.header.version = 0x01;	//Version: 802.1X-2001 (1)
	eap_header.header.length = htons(extLen + EAP_HDR_LEN);
	// Extensible Authentication Protocol
	eap_header.code = code;
	eap_header.id = id;
	eap_header.length = htons(extLen + EAP_HDR_LEN);
	eap_header.type = type;
	memcpy(packet + i, &eap_header, EAP_HDR_LEN + EAPOL_HDR_LEN);
	i += (EAPOL_HDR_LEN + EAP_HDR_LEN);

	memcpy(packet + i, extPkt, extLen);
	i += extLen;
	
	if (i < EAP_MIN_LEN)
	{
		memset(packet + i, 0x00, 60 - i);
		i = EAP_MIN_LEN;
	}
	// 发包
	pcap_sendpacket(adhandle, packet, i);
}

static void SendEAPOL(uint8_t type)
{
	uint8_t packet[64];
	eapol_header_t eapol_header; // eapol header

	// Fill Ethernet header
	memcpy(packet, &eth_header, ETH_LEN);

	// EAPOL header
	eapol_header.version = 0x01;	//Version: 802.1X-2001 (1)
	eapol_header.type = type;
	eapol_header.length = 0x00;

	memcpy(packet + 14, &eapol_header, EAPOL_HDR_LEN);

	memset(packet + 18, 0x00, (64 - ETH_LEN - EAPOL_HDR_LEN));	//剩余字节填充0


	// 发包
	pcap_sendpacket(adhandle, packet, sizeof(packet));
}

static void SendStartPkt()
{
	SendEAPOL(0x01);	// Type=Start
}

static void SendLogOffPkt()
{
	SendEAPOL(0x02);	// Type=Logoff
}

static void SendResponseNotification(const uint8_t request[])
{
	uint8_t response[50];

	assert((EAP_Code )request[18] == REQUEST);
	assert((EAP_Type )request[22] == NOTIFICATION);

	// Extensible Authentication Protocol
	size_t i = 0;
	/* Notification Data */
	// 其中前2+20字节为客户端版本
	response[i++] = 0x01; // type 0x01
	response[i++] = 0x16;   // lenth
	FillClientVersionArea(response + i);
	i += 20;

	SendEAPPacket((EAP_Code)RESPONSE, (EAP_Type)NOTIFICATION, request[19], response, i);
}


static void SendResponseSecurity(const uint8_t request[])
{
	size_t i = 0;
	size_t usernamelen;
	uint8_t response[100];

	assert((EAP_Code )request[18] == REQUEST);
	assert((EAP_Type )request[22] == SECURITY);

	// Extensible Authentication Protocol
	// Type-Data
	response[i++] = 0x00;	// 上报是否使用代理
	//暂时未能解密该部分内容，只作填充0处理
	/*
	response[i++] = 0x16;
	response[i++] = 0x20;	//Length
	//memcpy(response + i, pulse, 32);
	memset(response + i, 0x00, 32);
	i += 32;
				
	GetIpFromDevice(local_ip, deviceName);
	response[i++] = 0x15;	  // 上传IP地址
	response[i++] = 0x04;	  //
	memcpy(response + i, local_ip, 4);	  //
	i += 4;			  //
	*/
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

	SendEAPPacket((EAP_Code)RESPONSE, (EAP_Type)SECURITY, request[19], response, i);
}

static void SendResponseIdentity(const uint8_t request[])
{
	uint8_t response[100];
	size_t i = 0;
	size_t usernamelen;

	assert((EAP_Code )request[18] == REQUEST);

	// Extensible Authentication Protocol
	/*
	if(isConnected)
	{
		//连接后需要上报的内容
		//TODO:暂时未能解密该部分内容，只作填充0处理

		response[i++] = 0x16;
		response[i++] = 0x20;	//Length
		//memcpy(response + i, pulse, 32);
		memset(response+i, 0x00, 32);
		i += 32;
				
		GetIpFromDevice(local_ip, deviceName);
		response[i++] = 0x15;	  // 上传IP地址
		response[i++] = 0x04;	  //
		memcpy(response+i, local_ip, 4);//
		i += 4;
	}
	*/

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

	SendEAPPacket((EAP_Code)RESPONSE, (EAP_Type)IDENTITY, request[19], response, i);

}

static void SendResponseMD5(const uint8_t request[])
{
	size_t usernamelen;
	uint8_t response[40];
	size_t i = 0;
	assert((EAP_Code )request[18] == REQUEST);
	assert((EAP_Type )request[22] == MD5_CHALLENGE);

	usernamelen = strlen(username);

	// Extensible Authentication Protocol
	response[i++] = 16;		// Value-Size: 16 Bytes
	FillMD5Area(response + i, request[19], password, request + 24);
	i += 16;
	memcpy(response + i, username, usernamelen);
	i += usernamelen;
	assert(i <= sizeof(response));

	SendEAPPacket((EAP_Code)RESPONSE, (EAP_Type)MD5_CHALLENGE, request[19], response, i);
}

// 函数: XOR(data[], datalen, key[], keylen)
//
// 使用密钥key[]对数据data[]进行异或加密
//（注：该函数也可反向用于解密）
static void XOR(uint8_t data[], unsigned dlen, const char key[], unsigned klen)
{
	unsigned int i, j;

	// 先按正序处理一遍
	for (i = 0; i < dlen; i++)
		data[i] ^= key[i % klen];
	// 再按倒序处理第二遍
	for (i = dlen - 1, j = 0; j < dlen; i--, j++)
		data[i] ^= key[j % klen];
}

static void FillClientVersionArea(uint8_t area[20])
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

/*
static
void FillWindowsVersionArea(uint8_t area[20])
{
	const uint8_t WinVersion[20] = "r70393861";

	memcpy(area, WinVersion, 20);
	XOR(area, 20, H3C_KEY, strlen(H3C_KEY));
}*/

static void FillBase64Area(char area[])
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

static void FillMD5Area(uint8_t digest[], uint8_t id, const char passwd[], const uint8_t srcMD5[])
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
