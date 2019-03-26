#ifndef _TCP_H_
#define _TCP_H_

#include <stdint.h>

struct TcpHeader
{
	uint16_t thSport;
	uint16_t thDport;
	uint32_t thSeq;
	uint32_t thAck;
	uint8_t thOffx2;
#define TH_OFF(th)	(((th)->thOffx2 & 0xf0) >> 4)
	uint8_t thFlags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	uint16_t thWin;
	uint16_t thSum;
	uint16_t thUrp;
};

#endif