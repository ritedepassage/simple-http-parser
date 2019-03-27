#include "http.hh"

void HttpTracer::Trace(const unsigned char *payload, uint32_t payload_size, uint16_t src_port, uint16_t dst_port, uint32_t currentSeqNO) {

	switch (state) {

	case HTTP_STATE::UNKNOWN:
	{
		requestAccumulateSize += payload_size;
		for (size_t i{}; i < payload_size; i++)
			requestHeaders.push_back(payload[i]);

		break;
	}
	}
}