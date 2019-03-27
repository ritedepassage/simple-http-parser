#include "tcp.hh"

bool TcpStream::Trace(Flow &currentFlow, const TcpHeader *currentHeader) {

	switch (state)
	{
	case TCP_CONNECTION_STATE::UNKNOWN:
		if (currentHeader->thFlags & TH_SYN) {
			state = TCP_CONNECTION_STATE::SYN;

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