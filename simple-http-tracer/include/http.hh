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

public:

	HttpTracer(bool isinitial) : isInitial{isinitial}, state{ HTTP_STATE::UNKNOWN },
		requestHeaders{ "" }, responseHeaders{ "" }, requestUri{ "" } {

	}
};

#endif