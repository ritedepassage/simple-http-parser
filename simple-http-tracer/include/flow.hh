#ifndef _FLOW_H_
#define _FLOW_H_

#include <stdint.h>
#include <string>


class Flow {
public:
	uint8_t protocol;
	uint32_t srcAddr;
	uint32_t dstAddr;
	uint16_t srcPort;
	uint16_t dstPort;
	uint32_t offset;
	uint32_t totalSize;
	uint32_t ipTotalLen;
	uint32_t payloadLen;

	const unsigned char *payload;

	Flow() {
		memset((void *)this, 0, sizeof(Flow));
	}

	bool operator ==(const Flow& r_value) const {

		return protocol == r_value.protocol &&
			((srcAddr == r_value.srcAddr && srcPort == r_value.srcPort &&
			dstAddr == r_value.dstAddr && dstPort == r_value.dstPort) ||
			(srcAddr == r_value.dstAddr && srcPort == r_value.dstPort &&
			dstAddr == r_value.srcAddr && dstPort == r_value.srcPort));
	}
};

struct FlowHash {

	size_t operator()(const Flow &x) const {

		return x.srcAddr ^ x.dstAddr ^ x.protocol ^ x.srcPort ^ x.dstPort;
	}

};

#endif