/*
 * Filename:     adapter.c
 *
 * Created by:	 liuqun
 * Revised:      2015年4月19日
 * Revised by:   KiritoA
 * Description:  获取网卡设置的函数
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <pcap.h>

#include "adapter.h"

#if defined(WIN32)
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdlib.h>

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

void GetIpFromDevice(uint8_t ip[4], const char *deviceName)
{
#ifdef WIN32
	pcap_if_t *alldevs;
	pcap_if_t *dev;
	pcap_addr_t *paddr;
	SOCKADDR_IN *sin;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		//exit(1);
	}
	for (dev = alldevs; dev != NULL; dev = dev->next) {
		if (strcmp(dev->name, deviceName) == 0)
			paddr = dev->addresses;
	}
	for (; paddr; paddr = paddr->next)
	{
		sin = (SOCKADDR_IN *)paddr->addr;
		if (sin->sin_family == AF_INET)
		{
			memcpy(ip, &sin->sin_addr.s_addr, 4);
		}
	}

	pcap_freealldevs(alldevs);
#else

	int fd;
	struct ifreq ifr;

	assert(strlen(DeviceName) <= IFNAMSIZ);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(fd>0);

	strncpy(ifr.ifr_name, DeviceName, IFNAMSIZ);
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
	return;
#endif
}

void GetMacFromDevice(uint8_t mac[6], const char *deviceName)
{
#ifdef WIN32

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	UINT i;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(sizeof(IP_ADAPTER_INFO));
	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			if (memcmp(deviceName + 4, pAdapter->AdapterName, strlen(pAdapter->AdapterName) == 0))
			{
				for (i = 0; i < 6; i++) {
					mac[i] = pAdapter->Address[i];
				}
				break;
			}
			else
				pAdapter = pAdapter->Next;
		}

	}

	if (pAdapterInfo)
		FREE(pAdapterInfo);
#else
	int fd;
	int err;
	struct ifreq ifr;

	fd = socket(PF_PACKET, SOCK_RAW, htons(0x0806));
	assert(fd != -1);

	assert(strlen(devicename) < IFNAMSIZ);
	strncpy(ifr.ifr_name, devicename, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;

	err = ioctl(fd, SIOCGIFHWADDR, &ifr);
	assert(err != -1);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

	err = close(fd);
	assert(err != -1);
#endif
}

void ListAllAdapters()
{
	pcap_if_t *alldevs;

	size_t i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	fprintf(stderr, "Adapters available:\n");

	if (pcap_findalldevs(&alldevs, errbuf) == 0){
		while (!(alldevs == NULL)){
			
			fprintf(stderr, "Name:\t\t");
			for (i = 0; i < strlen(alldevs->description); i++)
			{
				putchar(alldevs->description[i]);
			}
			fprintf(stderr, "\nDevice name:\t%s\n\n", alldevs->name);
			alldevs = alldevs->next;
			i++;
		}
	}
	pcap_freealldevs(alldevs);
}
