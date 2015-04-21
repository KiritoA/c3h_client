/*
 * Filename:     auth.h
 *
 * Created by:	 KiritoA
 * Revised:      2015年4月19日
 * Revised by:   KiritoA
 * Description:  801.1X认证核心函数
 *
 */
#ifndef SRC_AUTH_H_
#define SRC_AUTH_H_

#include <stdint.h>
#include <pcap.h>

void InitDevice(const char *DeviceName);
void CloseDevice();

int Authentication(const char *UserName, const char *Password);

void LogOff();

#endif /* SRC_AUTH_H_ */
