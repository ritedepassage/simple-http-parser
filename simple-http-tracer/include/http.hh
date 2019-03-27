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

enum class HTTP_RESPONSE_PARSE_RESULT
{
	OK = 200,
	PARSE_INCOMPLETE,
	EXCEEDED,
	RESPONSE_START_NOT_EXPECTED,
	RESPONSE_STATUS_CODE_ERROR,
	CONTENT_LENGTH_HEADER_NOT_FOUND,
	CONTENT_LENGTH_NOT_FOUND,
};

enum class HTTP_STATE
{
	UNKNOWN,
	HTTP_GET_RESOLVED,
	HTTP_REQUEST_COMPLETED,
	HTTP_RESPONSE_START_RESOLVED,
	HTTP_RESPONSE_HEADERS_COMPLETED,
	HTTP_CONTECNT_COMPLETED
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
	uint32_t responseAccumulateSize;
	unsigned long long contentLength;
	unsigned long long accumulateContentSize;

public:

	HttpTracer(bool isinitial) : isInitial{ isinitial }, state{ HTTP_STATE::UNKNOWN },
		requestHeaders{ "" }, responseHeaders{ "" }, requestUri{ "" },
		requestAccumulateSize{ 0 }, responseAccumulateSize{ 0 }, contentLength{ 0 }, accumulateContentSize{0} {

	}

	HTTP_REQUEST_PARSE_RESULT ParseRequestHeader();
	HTTP_RESPONSE_PARSE_RESULT ParseResponseHeader(uint32_t &headersSize);
	void Trace(const unsigned char *payload, uint32_t payload_size, uint16_t src_port, uint16_t dst_port, uint32_t currentSeqNO);
};

#endif