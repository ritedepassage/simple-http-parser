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

HTTP_RESPONSE_PARSE_RESULT HttpTracer::ParseResponseHeader(uint32_t &headersSize) {

	headersSize = 0;

	if (responseAccumulateSize < 4) { //not enough
		return HTTP_RESPONSE_PARSE_RESULT::PARSE_INCOMPLETE;
	}
	if (responseAccumulateSize > 1500) { //larger than expected
		return HTTP_RESPONSE_PARSE_RESULT::EXCEEDED;
	}

	size_t endOfHeaders = responseHeaders.find("\r\n\r\n");

	if (endOfHeaders == std::string::npos)
		return HTTP_RESPONSE_PARSE_RESULT::PARSE_INCOMPLETE;

	size_t responseStart = responseHeaders.find("HTTP");
	if (responseStart == std::string::npos || responseStart > 0)
		return HTTP_RESPONSE_PARSE_RESULT::RESPONSE_START_NOT_EXPECTED;

	responseStart += 4;

	responseStart = responseHeaders.find("200 OK\r\n", responseStart);

	if (responseStart == std::string::npos)
		return HTTP_RESPONSE_PARSE_RESULT::RESPONSE_STATUS_CODE_ERROR;

	responseStart = responseHeaders.find("Content-Length", responseStart);

	if (responseStart == std::string::npos)
		return HTTP_RESPONSE_PARSE_RESULT::CONTENT_LENGTH_HEADER_NOT_FOUND;

	responseStart = responseHeaders.find_first_of("0123456789", responseStart);
	if (responseStart == std::string::npos)
		return HTTP_RESPONSE_PARSE_RESULT::CONTENT_LENGTH_NOT_FOUND;

	try {
		contentLength = std::stol(responseHeaders.substr(responseStart));
	}
	catch (...) {
		return HTTP_RESPONSE_PARSE_RESULT::CONTENT_LENGTH_NOT_FOUND;
	}

	headersSize = endOfHeaders + 4;

	return 	HTTP_RESPONSE_PARSE_RESULT::OK;
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
		accumulateContentSize = 0;
		requestHeaders.clear();
	}
		break;
	case HTTP_STATE::HTTP_REQUEST_COMPLETED:
	{
		uint32_t headersSize{ 0 };

		responseAccumulateSize += payload_size;
		for (size_t i{}; i < payload_size; i++)
			responseHeaders.push_back(payload[i]);

		HTTP_RESPONSE_PARSE_RESULT reponseParseRes = ParseResponseHeader(headersSize);

		if (reponseParseRes == HTTP_RESPONSE_PARSE_RESULT::PARSE_INCOMPLETE)
			return;

		if (reponseParseRes == HTTP_RESPONSE_PARSE_RESULT::OK) {

			state = HTTP_STATE::HTTP_RESPONSE_HEADERS_COMPLETED;
			accumulateContentSize = 0;

			if (!binaryWriter.is_open()) {
				std::stringstream ss;
				ss << src_port << "-" << dst_port << "-" << requestUri << "-" << contentLength << ".bin";
				streamUniqueName = ss.str();
				binaryWriter.open(streamUniqueName.c_str(), std::ios::out | std::ios::binary);
			}

			if (headersSize < responseHeaders.size()) {

				uint32_t currentContentLen = responseHeaders.size() - headersSize;

				binaryWriter.write((const char*)&responseHeaders[headersSize], currentContentLen);

				contentLength -= currentContentLen;
				accumulateContentSize += currentContentLen;

				if (contentLength <= 0) {

					state = HTTP_STATE::UNKNOWN;
					binaryWriter.close();
				}
			}
		}
		else {
			state = HTTP_STATE::UNKNOWN;
		}

		responseAccumulateSize = 0;
		responseHeaders.clear();
	}
		break;
	case HTTP_STATE::HTTP_RESPONSE_HEADERS_COMPLETED:
	{
		binaryWriter.write((const char *)payload, payload_size);

		contentLength -= payload_size;
		accumulateContentSize += payload_size;


		if (contentLength <= 0) {

			state = HTTP_STATE::UNKNOWN;
			accumulateContentSize = 0;
			binaryWriter.close();
		}
	}
		break;
	}
}