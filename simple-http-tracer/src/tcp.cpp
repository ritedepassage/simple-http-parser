#include "tcp.hh"

void TcpReassembly::Initialize(uint32_t initialSeqNo) {

	CurrentSeqNo = InitialSeqNo = initialSeqNo;
	ExpectedSeqNo = CurrentSeqNo + 1;
}

//According to RFC 1982: Section 3.2 (Comparison)
int32_t TcpReassembly::CompareSequenceNumbers(uint32_t seq1, uint32_t seq2) {

	return (int32_t)(seq1 - seq2);
}

bool TcpReassembly::InspectSeqNumber(Flow &currentFlow, uint32_t currentSeqNo) {

	CurrentSeqNo = currentSeqNo;

	int32_t seqCompareRes = CompareSequenceNumbers(CurrentSeqNo, ExpectedSeqNo);

	if (seqCompareRes == 0) { //CurrentSeqNo == ExpectedSeqNo

		ExpectedSeqNo += currentFlow.payloadLen;


		if (currentFlow.payloadLen > 0) {

		}

		return true;
	}
	else if (seqCompareRes < 0) { //CurrentSeqNo < ExpectedSeqNo

		return false;

	}
	else { //CurrentSeqNo > ExpectedSeqNo

	}

	return false;
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

			if (InitialSide.InspectSeqNumber(currentFlow, currentSeq)) {

				state = TCP_CONNECTION_STATE::ESTABLISHED;
				return true;
			}
			return false;
		}
		else {

			return false;
		}
		break;
	case TCP_CONNECTION_STATE::ESTABLISHED:

		reassembler->InspectSeqNumber(currentFlow, currentSeq);

		break;
	default:
		break;
	}

	return false;
}