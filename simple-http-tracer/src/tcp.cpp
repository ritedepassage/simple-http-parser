#include "tcp.hh"

void TcpReassembly::Initialize(uint32_t initialSeqNo) {

	CurrentSeqNo = InitialSeqNo = initialSeqNo;
	ExpectedSeqNo = CurrentSeqNo + 1;
}

bool TcpStream::Trace(Flow &currentFlow, const TcpHeader *currentHeader) {

	uint32_t currentSeq = ntohl(currentHeader->thSeq);

	TcpReassembly *reassembler{ nullptr };

	if (currentFlow.srcAddr == InitialFlow.srcAddr) {

		reassembler = &InitialSide;
	}
	else {

		reassembler = &ReverseSide;
	}

	switch (state)
	{
	case TCP_CONNECTION_STATE::UNKNOWN:
		if (currentHeader->thFlags & TH_SYN) {

			state = TCP_CONNECTION_STATE::SYN;
			InitialSide.Initialize(currentSeq);
		}
		else {
			return false;
		}
		break;
	case TCP_CONNECTION_STATE::SYN:
		if ((currentHeader->thFlags & TH_SYN) && (currentHeader->thFlags & TH_ACK)) {

			state = TCP_CONNECTION_STATE::SYN_ACK;

			return true;
		}
		else {

			return false;
		}
		break;
	case TCP_CONNECTION_STATE::SYN_ACK:
		if (currentHeader->thFlags & TH_ACK) {

			state = TCP_CONNECTION_STATE::ESTABLISHED;
			return true;

		}
		else {

			return false;
		}
		break;
	case TCP_CONNECTION_STATE::ESTABLISHED:

		return true;

		break;
	default:
		break;
	}

	return false;
}