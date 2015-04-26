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

#define AUTH_PROGRESS_DISCONNECT	0
#define AUTH_PROGRESS_START			1
#define AUTH_PROGRESS_INENTITY		2
#define AUTH_PROGRESS_PASSWORD		3
#define AUTH_PROGRESS_CONNECTED		4

#define ERR_NOT_RESPOND				-1
#define ERR_UNKNOWN_FAILED			100
#define ERR_AUTH_FAILED				101
#define ERR_AUTH_INVALID_VERSION	102
#define ERR_AUTH_TIME_LIMIT			103

#define ETH_LEN	14
typedef struct{
	uint8_t dest_mac[6];
	uint8_t src_mac[6];
	uint16_t eth_type;
}eth_header_t;

#define EAPOL_HDR_LEN	4
typedef struct{
	uint8_t version;
	uint8_t type;
	uint16_t length;
}eapol_header_t;

#define EAP_MIN_LEN	60
#define EAP_HDR_LEN	5
typedef struct{
	eapol_header_t header;
	//EAP
	uint8_t code;
	uint8_t id;
	uint16_t length;
	uint8_t type;
}eap_header_t;

void InitDevice(const char *DeviceName);
void CloseDevice();

int Authentication(const char *UserName, const char *Password);

void LogOff();

#endif /* SRC_AUTH_H_ */
