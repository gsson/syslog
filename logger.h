/*
 * Copyright (c) 2013, Henrik Gustafsson <gsson@fnord.se>
 *
 * Permission to use, copy, modify, and/or distribute this
 * software for any purpose with or without fee is hereby
 * granted, provided that the above copyright notice and this
 * permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
 * CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */
#ifndef LOGGER_H_
#define LOGGER_H_

#include <pthread.h>

#define LGR_MAX_MESSAGE 2048

enum logger_framing {
	LGR_FRAMING_NL = 0,
	LGR_FRAMING_SYSLOG = 1,
	LGR_FRAMING_SYSLOG_OC = 2,
	LGR_FRAMING_SYSLOG_NL = 3
};

enum logger_protocol {
	LGR_UDP,
	LGR_TCP,
	LGR_UNIX_DGRAM,
	LGR_UNIX_STREAM,
	LGR_STDOUT,
	LGR_STDERR,
	LGR_FILE
};

enum logger_severity {
	LGR_SEV_EMERG=0,
	LGR_SEV_ALERT=1,
	LGR_SEV_CRIT=2,
	LGR_SEV_ERR=3,
	LGR_SEV_WARNING=4,
	LGR_SEV_NOTICE=5,
	LGR_SEV_INFO=6,
	LGR_SEV_DEBUG=7
};

enum logger_facility {
	LGR_FAC_KERN=0,
	LGR_FAC_USER=1,
	LGR_FAC_MAIL=2,
	LGR_FAC_DAEMON=3,
	LGR_FAC_AUTH=4,
	LGR_FAC_SYSLOG=5,
	LGR_FAC_LPR=6,
	LGR_FAC_NEWS=7,
	LGR_FAC_UUCP=8,
	LGR_FAC_CRON=9,
	LGR_FAC_AUTHPRIV=10,
	LGR_FAC_FTP=11,
	LGR_FAC_LOCAL0=16,
	LGR_FAC_LOCAL1=17,
	LGR_FAC_LOCAL2=18,
	LGR_FAC_LOCAL3=19,
	LGR_FAC_LOCAL4=20,
	LGR_FAC_LOCAL5=21,
	LGR_FAC_LOCAL6=22,
	LGR_FAC_LOCAL7=23
};

struct logger_config {
	enum logger_facility facility;
	enum logger_severity severity;
	enum logger_protocol protocol;
	enum logger_framing framing;
	char *address;
	char *port;
	char **fields;
};

struct logger_tl;
struct logger;

/**
 * Inline rendering function
 *
 * @param buf The buffer to render into
 * @param maxlen The maximum length of message
 * @param arg The value provided to the logger_render() function
 *
 * @return The length of the message in bytes.
 */
typedef int (* render_fn)(char *buf, int maxlen, void *arg);

typedef int (* write_fn)(struct logger *logger, struct logger_tl *tl, size_t msg_len);
typedef void (* close_fn)(struct logger *logger, int oldFd);
typedef int (* connect_fn)(enum logger_protocol protocol, const char *addr, const char *service);

struct logger {
	pthread_t thread;
	pthread_key_t tl;
    pthread_mutex_t connector_lock;
    pthread_cond_t connector_cond;
    pthread_cond_t connection_cond;
    pthread_mutex_t connection_lock;
    int running;
	int pri;
	int fd;
	char meta[64];
	struct logger_config config;
	connect_fn connect;
	write_fn write;
	close_fn close;
};

/**
 * Open logger
 *
 * @param logger The logger structure to initialize
 * @param config The logger configuration
 */
void logger_open(struct logger *logger, struct logger_config *config);

/**
 * Close logger
 *
 * NOTE: failing to close the logger will leak memory, threads and file descriptors
 *
 * @param logger The logger to close
 */
void logger_close(struct logger *logger);

/**
 * Wait for logger to become connected
 *
 * @param logger The logger to wait for
 */
void logger_wait(struct logger *logger);

/* Log stuff */

/**
 * Send message
 *
 * @param logger The logger to send to.
 * @param msg The message to send.
 */
int logger_log(struct logger *logger, const char *msg);

/**
 * Send formatted message
 *
 * @param logger The logger to send to.
 * @param fmt The formatting template (Uses printf() syntax)
 * @param ... The formatting arguments
 */
int logger_logf(struct logger *logger, const char *fmt, ...);

/**
 * Inline rendering function
 *
 * Copy data into the send-buffer, potentially bypassing one level of buffer copies.
 *
 * @param logger The logger to send to.
 * @param renderer The rendering function.
 * @param arg The argument to pass to the rendering function.
 */
int logger_render(struct logger *logger, render_fn renderer, void *arg);

#endif /* LOGGER_H_ */
