#ifndef _IP_H_
#define _IP_H_

#include <stdint.h>
#include <winsock2.h>

struct IpHeader {

	uint8_t ipVhl;
	uint8_t ipTos;	
	uint16_t ipLen;
	uint16_t ipId;	
	uint16_t ipOff;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
	uint8_t ipTtl;
	uint8_t ipP;
	uint16_t ipSum;
	struct in_addr ipSrc, ipDst;
};
#define IP_HL(ip)		(((ip)->ipVhl) & 0x0f)
#define IP_V(ip)		(((ip)->ipVhl) >> 4)

#endif