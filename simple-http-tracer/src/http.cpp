#include "http.hh"

HTTP_REQUEST_PARSE_RESULT HttpTracer::ParseRequestHeader() {

	if (requestAccumulateSize < 4) { //not enough
		return HTTP_REQUEST_PARSE_RESULT::PARSE_INCOMPLETE;
	}
	if (requestAccumulateSize > 1500) { //larger the expected
		return HTTP_REQUEST_PARSE_RESULT::EXCEEDED;
	}

	size_t pos = requestHeaders.find("\r\n\r\n");

	if (pos == std::string::npos)
		return HTTP_REQUEST_PARSE_RESULT::PARSE_INCOMPLETE;

	if (requestHeaders[0] != 'G' || requestHeaders[1] != 'E' || requestHeaders[2] != 'T') {
		return HTTP_REQUEST_PARSE_RESULT::REQUEST_START_NOT_EXPECTED;
	}

	size_t methodHeaderStart = requestHeaders.find("\r\n");
	if (methodHeaderStart < 8)
		return HTTP_REQUEST_PARSE_RESULT::METHOD_HEADER_TOO_SHORT;

	size_t httpStart = requestHeaders.find("HTTP/", methodHeaderStart - 8);

	if (httpStart == std::string::npos)
		return HTTP_REQUEST_PARSE_RESULT::METHOD_HEADER_HTTP_NOT_FOUND;

	size_t uriStart{ 3 };
	uriStart = requestHeaders.find_first_of(' ', uriStart);
	if (uriStart == std::string::npos)
		return HTTP_REQUEST_PARSE_RESULT::REQUEST_URI_SEPARATOR_NOT_FOUND;

	uriStart += 1;
	uriStart = requestHeaders.find_first_not_of(' ', uriStart);
	if (uriStart == std::string::npos)
		return HTTP_REQUEST_PARSE_RESULT::REQUEST_URI_SEPARATOR_NOT_FOUND;

	size_t uriEnd = requestHeaders.find_first_of(' ', uriStart);
	if (uriEnd == std::string::npos)
		return HTTP_REQUEST_PARSE_RESULT::REQUEST_URI_SEPARATOR_NOT_FOUND;

	requestUri = requestHeaders.substr(uriStart, uriEnd - uriStart);

	requestUri.erase(std::remove_if(requestUri.begin(), requestUri.end(),
		[](char const& c) -> bool { return !std::isalnum(c); }), requestUri.end());

	if (requestUri == "")
		requestUri = requestUri.append("root");

	return HTTP_REQUEST_PARSE_RESULT::OK;
}


void HttpTracer::Trace(const unsigned char *payload, uint32_t payload_size, uint16_t src_port, uint16_t dst_port, uint32_t currentSeqNO) {

	switch (state) {

	case HTTP_STATE::UNKNOWN:
	{
		requestAccumulateSize += payload_size;
		for (size_t i{}; i < payload_size; i++)
			requestHeaders.push_back(payload[i]);

		HTTP_REQUEST_PARSE_RESULT requestParseRes = ParseRequestHeader();

		if (requestParseRes == HTTP_REQUEST_PARSE_RESULT::PARSE_INCOMPLETE)
			return;

		if (requestParseRes == HTTP_REQUEST_PARSE_RESULT::OK) {

			state = HTTP_STATE::HTTP_REQUEST_COMPLETED;
		}

		requestAccumulateSize = 0;
		requestHeaders.clear();

		break;
	}
	}
}