/*
 * Filename:     adapter.c
 *
 * Created by:	 liuqun
 * Revised by:   KiritoA
 * Description:  获取网卡设置的函数
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <pcap.h>

#include "defs.h"
#include "adapter.h"

#if defined(WIN32)
#include <winsock2.h>
#include <iphlpapi.h>   
#include <stdbool.h>
#pragma comment(lib, "IPHLPAPI.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

#else
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

int GetIpFromDevice(uint8_t ip[4], const char *deviceName)
{
#ifdef WIN32
	pcap_if_t *alldevs;
	pcap_if_t *dev;
	pcap_addr_t *paddr = NULL;
	SOCKADDR_IN *sin;
	bool found = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		PRINTERR("Error in pcap_findalldevs: %s\n", errbuf);
		return 1;
	}
	for (dev = alldevs; dev != NULL; dev = dev->next) {
		if (strcmp(dev->name, deviceName) == 0)
		{
			paddr = dev->addresses;
			break;
		}
	}
	for (; paddr; paddr = paddr->next)
	{
		sin = (SOCKADDR_IN *)paddr->addr;
		if (sin->sin_family == AF_INET)
		{
			memcpy(ip, &sin->sin_addr.s_addr, 4);
			found = true;
		}
	}

	if(!found)
	{
		// 查询不到IP时默认填零处理
		memset(ip, 0x00, 4);
	}

	pcap_freealldevs(alldevs);

	return 0;

#else

	int fd;
	struct ifreq ifr;

	assert(strlen(deviceName) <= IFNAMSIZ);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(fd>0);

	strncpy(ifr.ifr_name, deviceName, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl(fd, SIOCGIFADDR, &ifr) == 0)
	{
		struct sockaddr_in *p = (void*) &(ifr.ifr_addr);
		memcpy(ip, &(p->sin_addr), 4);
	}
	else
	{
		// 查询不到IP时默认填零处理
		memset(ip, 0x00, 4);
	}

	close(fd);
	return 0;
#endif
}

int GetMacFromDevice(uint8_t mac[6], const char *deviceName)
{
#ifdef WIN32

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;

	if (strlen(deviceName) <= 12)
		return 1;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		return 1;
	}
	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			return 1;
		}
	}
	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			if (strcmp(deviceName + 12, pAdapter->AdapterName) == 0)
			{
				memcpy(mac, pAdapter->Address, 6);

				break;
			}
			else
				pAdapter = pAdapter->Next;
		}

	}

	if (pAdapterInfo)
		FREE(pAdapterInfo);

	return 0;
#else
	int fd;
	int err;
	struct ifreq ifr;

	fd = socket(PF_PACKET, SOCK_RAW, htons(0x0806));
	assert(fd != -1);

	assert(strlen(deviceName) < IFNAMSIZ);
	strncpy(ifr.ifr_name, deviceName, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;

	err = ioctl(fd, SIOCGIFHWADDR, &ifr);
	assert(err != -1);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

	err = close(fd);
	assert(err != -1);
	return err;
#endif
}

void ListAllAdapters()
{
	pcap_if_t *alldevs;

	size_t i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	PRINT("Adapters available:\n");

	if (pcap_findalldevs(&alldevs, errbuf) == 0){
		while (!(alldevs == NULL)){
#ifdef WIN32
			PRINT("Name:\t%s\n", alldevs->description);
			PRINT("ID:\t%s\n", alldevs->name);
			PRINT("-------------------------------\n");
#else
			PRINT("%s\n", alldevs->name);
#endif
			alldevs = alldevs->next;
			i++;
		}
	}
	pcap_freealldevs(alldevs);
}

int RefreshIPAddress()
{
#ifdef WIN32

	return system("ipconfig /renew");
#else
	return system("./c3h-refresh");
#endif
}
