#ifndef _TCP_H_
#define _TCP_H_

#include <vector>
#include <algorithm>

#include "http.hh"

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

enum class TCP_CONNECTION_STATE
{
	UNKNOWN,
	SYN,
	SYN_ACK,
	ESTABLISHED
};

class UnorderedPacket
{
private:
	static const uint16_t MAX_PAYLOAD_SIZE{ 1500 };

public:
	unsigned char payload[MAX_PAYLOAD_SIZE];
	uint16_t payloadSize;
	uint32_t seqNo;

	UnorderedPacket(const unsigned char *data, uint16_t size, uint32_t currentSeqNo) {

		if (size <= MAX_PAYLOAD_SIZE) { //jumbo frames (greater than max payload size) are not supported
			payloadSize = size;
			memcpy(payload, data, size);
			seqNo = currentSeqNo;
		}
	}
};

class TcpReassembly
{
private:
	std::vector<UnorderedPacket> unorderedPackets;
	uint32_t InitialSeqNo;
	uint32_t CurrentSeqNo;
	uint32_t ExpectedSeqNo;
	HttpTracer *httpTracer{ nullptr };

	int32_t CompareSequenceNumbers(uint32_t seq1, uint32_t seq2);

public:
	bool isInitial;

	TcpReassembly(bool i_isInitial, HttpTracer *httptracer) : isInitial{ i_isInitial },
		InitialSeqNo{ 0 }, CurrentSeqNo{ 0 }, ExpectedSeqNo{ 0 }, httpTracer{ httptracer } {

	}

	void Initialize(uint32_t initialSeqNo);
	bool InspectSeqNumber(Flow &currentFlow, uint32_t currentSeqNo);
	void FindUnorderedPacket(Flow &currentFlow);
};

class TcpStream
{
private:
	HttpTracer httpTracer{ false };
	TcpReassembly InitialSide{ true, &httpTracer };
	TcpReassembly ReverseSide{ false, &httpTracer };

	Flow InitialFlow;
	TCP_CONNECTION_STATE state;

public:

	TcpStream(Flow& initialFlow) : state{ TCP_CONNECTION_STATE::UNKNOWN }, InitialFlow{ initialFlow } {
	}

	bool Trace(Flow &currentFlow, const TcpHeader *currentHeader);
};

#endif