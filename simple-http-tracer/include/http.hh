#ifndef _HTTP_H_
#define _HTTP_H_

#include <string>

#include "flow.hh"

enum class HTTP_STATE
{
	UNKNOWN
};

class HttpTracer
{
private:
	bool isInitial;
	HTTP_STATE state;
	std::string requestHeaders;
	std::string responseHeaders;
	std::string requestUri;
	uint32_t requestAccumulateSize;

public:

	HttpTracer(bool isinitial) : isInitial{isinitial}, state{ HTTP_STATE::UNKNOWN },
		requestHeaders{ "" }, responseHeaders{ "" }, requestUri{ "" } {

	}

	void Trace(const unsigned char *payload, uint32_t payload_size, uint16_t src_port, uint16_t dst_port, uint32_t currentSeqNO);
};

#endif