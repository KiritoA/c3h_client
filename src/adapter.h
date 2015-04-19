/*
 * Filename:     adapter.h
 *
 * Created by:	 liuqun
 * Revised:      2015年4月19日
 * Revised by:   KiritoA
 * Description:  获取网卡设置的函数
 *
 */
#ifndef SRC_ADAPTER_H_
#define SRC_ADAPTER_H_

void GetIpFromDevice(uint8_t ip[4], const char *deviceName);
void GetMacFromDevice(uint8_t mac[6], const char *devicename);
void ListAllAdapters();

#endif /* SRC_ADAPTER_H_ */
