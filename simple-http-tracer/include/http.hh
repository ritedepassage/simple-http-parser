#ifndef _HTTP_H_
#define _HTTP_H_

#include <string>
#include <algorithm>
#include <cctype>

#include "flow.hh"

enum class HTTP_REQUEST_PARSE_RESULT
{
	OK = 400,
	PARSE_INCOMPLETE,
	EXCEEDED,
	REQUEST_START_NOT_EXPECTED,
	METHOD_HEADER_TOO_SHORT,
	METHOD_HEADER_HTTP_NOT_FOUND,
	REQUEST_URI_SEPARATOR_NOT_FOUND
};

enum class HTTP_STATE
{
	UNKNOWN,
	HTTP_REQUEST_COMPLETED
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

	HttpTracer(bool isinitial) : isInitial{ isinitial }, state{ HTTP_STATE::UNKNOWN },
		requestHeaders{ "" }, responseHeaders{ "" }, requestUri{ "" }, requestAccumulateSize{0} {

	}

	HTTP_REQUEST_PARSE_RESULT ParseRequestHeader();
	void Trace(const unsigned char *payload, uint32_t payload_size, uint16_t src_port, uint16_t dst_port, uint32_t currentSeqNO);
};

#endif