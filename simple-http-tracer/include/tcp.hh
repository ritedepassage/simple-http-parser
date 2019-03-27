#ifndef _TCP_H_
#define _TCP_H_

#include <stdint.h>

#include "flow.hh"

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

class TcpReassembly
{
private:

	int32_t CompareSequenceNumbers(uint32_t seq1, uint32_t seq2);

public:
	bool isInitial;
	uint32_t InitialSeqNo;
	uint32_t CurrentSeqNo;
	uint32_t ExpectedSeqNo;


	TcpReassembly(bool i_isInitial) : isInitial{ i_isInitial }, InitialSeqNo{ 0 }, CurrentSeqNo{ 0 }, ExpectedSeqNo{ 0 }{

	}

	void Initialize(uint32_t initialSeqNo);
	bool InspectSeqNumber(Flow &currentFlow, uint32_t currentSeqNo);
};

class TcpStream
{
private:

	TcpReassembly InitialSide{ true };
	TcpReassembly ReverseSide{ false };

	Flow InitialFlow;
	TCP_CONNECTION_STATE state;
public:

	TcpStream(Flow& initialFlow) : state{ TCP_CONNECTION_STATE::UNKNOWN }, InitialFlow{ initialFlow } {
	}

	bool Trace(Flow &currentFlow, const TcpHeader *currentHeader);
};

#endif