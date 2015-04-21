/*
 * Filename:     adapter.h
 *
 * Created by:	 KiritoA
 * Revised by:   KiritoA
 * Description:  获取网卡设置的函数
 *
 */
#ifndef SRC_ADAPTER_H_
#define SRC_ADAPTER_H_

int GetIpFromDevice(uint8_t ip[4], const char *deviceName);
int GetMacFromDevice(uint8_t mac[6], const char *devicename);
void ListAllAdapters();
int RefreshIPAddress();

#endif /* SRC_ADAPTER_H_ */
