#include <stdio.h>
#include <string.h>

#include "logger.h"

static const char CONST_MSG[] = "Rendered: 234, 2345, 2345";

static int
render(char *buf, int len, void *arg) {
	return strlcpy(buf, arg, len);
}

int
main(int argc, char **argv) {
	/*
	struct logger_config config = {
		LGR_FAC_LOCAL6,
		LGR_SEV_ALERT,
		LGR_TCP,
		LGR_FRAMING_SYSLOG_OC,
		"127.0.0.1",
		"514",
		NULL
	};
	*/
	/*
	struct logger_config config = {
		LGR_FAC_LOCAL6,
		LGR_SEV_ALERT,
		LGR_UDP,
		LGR_FRAMING_SYSLOG,
		"127.0.0.1",
		"syslog",
		NULL
	};
	*/
	/*
	struct logger_config config = {
		LGR_FAC_LOCAL6,
		LGR_SEV_ALERT,
		LGR_UNIX_DGRAM,
		LGR_FRAMING_SYSLOG,
		"/var/run/syslog",
		NULL,
		NULL
	};
	*/

	struct logger_config config = {
		LGR_FAC_LOCAL6,
		LGR_SEV_ALERT,
		LGR_FILE,
		LGR_FRAMING_NL,
		"/tmp/logger_test.log",
		NULL,
		NULL
	};

	struct logger logger;
	int i;

	logger_open(&logger, &config);
	logger_wait(&logger);

	for (i = 0; i < 10000; i++) {
		logger_logf(&logger, "Formatted: %s, %d, %s", "234", 2345, "2345");
		logger_log(&logger, "Static: 234, 2345, 2345");
		logger_render(&logger, render, (void *) CONST_MSG);
	}

	logger_close(&logger);
	return 0;
}
