#ifndef _ETHERNET_H_
#define _ETHERNET_H_

#include <stdint.h>

#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET   14

struct EthernetHeader {

	uint8_t etherDhost[ETHER_ADDR_LEN];
	uint8_t etherShost[ETHER_ADDR_LEN];
	uint16_t etherType;
};


#endif