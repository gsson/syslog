#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

#include "logger.h"

#define MAX_LEN_LEN 8 /* Max length of framing, 9999999 byte messages should be enough for everyone. */
#define BUFFER_SIZE (LGR_MAX_MESSAGE + MAX_LEN_LEN)

static int _fd_write_nl_framing(struct logger *, struct logger_tl *, size_t);
static int _fd_write_no_framing(struct logger *, struct logger_tl *, size_t);
static int _fd_write_oc_framing(struct logger *, struct logger_tl *, size_t);
static int _fd_send_nl_framing(struct logger *, struct logger_tl *, size_t);
static int _fd_send_no_framing(struct logger *, struct logger_tl *, size_t);
static int _fd_send_oc_framing(struct logger *, struct logger_tl *, size_t);

#define WRITEFN_SEND_OFFSET 0
#define WRITEFN_WRITE_OFFSET 4

static write_fn WRITEFNS[] = {
	_fd_send_nl_framing,
	_fd_send_no_framing,
	_fd_send_oc_framing,
	_fd_send_nl_framing,
	_fd_write_nl_framing,
	_fd_write_no_framing,
	_fd_write_oc_framing,
	_fd_write_nl_framing
};

static const char *HUNDRED[] = {
		"00", "01", "02", "03", "04", "05", "06", "07", "08", "09",
		"10", "11", "12", "13", "14", "15", "16", "17", "18", "19",
		"20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
		"30", "31", "32", "33", "34", "35", "36", "37", "38", "39",
		"40", "41", "42", "43", "44", "45", "46", "47", "48", "49",
		"50", "51", "52", "53", "54", "55", "56", "57", "58", "59",
		"60", "61", "62", "63", "64", "65", "66", "67", "68", "69",
		"70", "71", "72", "73", "74", "75", "76", "77", "78", "79",
		"80", "81", "82", "83", "84", "85", "86", "87", "88", "89",
		"90", "91", "92", "93", "94", "95", "96", "97", "98", "99"
};


struct logger_tl {
	char buf[BUFFER_SIZE];
	char *msg_start;
	char *timestamp;
	int max_timestamp;
	char *meta;
	int max_meta;
	char *message;
	int max_message;
	time_t last_clock;
};


static char *
_render_size(struct logger_tl *tl, int msg_len) {
	int n = msg_len, r = 0;
	char *p = tl->msg_start - 1;
	const char *c;
	if (n == 0) {
		*(--p) = '0';
	}
	while (n >= 10) {
		r = n % 100;
		n = n / 100;
		c = HUNDRED[r];
		*(--p) = c[1];
		*(--p) = c[0];
	}
	if (n > 0) {
		c = HUNDRED[n];
		*(--p) = c[1];
	}
	return p;
}

static void
_close_real(struct logger *logger, int oldFd) {
	if (!__sync_bool_compare_and_swap(&logger->fd, oldFd, -1)) {
		close(oldFd);
		if (pthread_cond_broadcast(&logger->connection_cond))
			err(1, "pthread_cond_broadcast()");
		if (pthread_cond_broadcast(&logger->connector_cond))
			err(1, "pthread_cond_broadcast()");
	}
}

static void
_close_fake(struct logger *logger, int oldFd) {
	if (!__sync_bool_compare_and_swap(&logger->fd, oldFd, -1)) {
		if (pthread_cond_broadcast(&logger->connection_cond))
			err(1, "pthread_cond_broadcast()");
		if (pthread_cond_broadcast(&logger->connector_cond))
			err(1, "pthread_cond_broadcast()");
	}
}

static int
_send(struct logger *logger, char *buf, int len) {
	int fd = logger->fd;
	if (fd != -1)
		return 1;

	if (send(fd, buf, len, 0) == -1) {
		warn("send()");
		logger->close(logger, fd);
		return 1;
	}
	return 0;
}

static int
_write(struct logger *logger, char *buf, int len) {
	int fd = logger->fd;
	if (fd == -1)
		return 1;

	if (write(fd, buf, len) == -1) {
		warn("write()");
		logger->close(logger, fd);
		return 1;
	}
	return 0;
}

static int
_fd_send_no_framing(struct logger *logger, struct logger_tl *tl, size_t msg_len) {
	return _send(logger, tl->msg_start, msg_len);
}

static int
_fd_send_oc_framing(struct logger *logger, struct logger_tl *tl, size_t msg_len) {
	char *buf = _render_size(tl, msg_len);
	int len = msg_len + (tl->msg_start - buf);
    return _send(logger, buf, len);
}

static int
_fd_send_nl_framing(struct logger *logger, struct logger_tl *tl, size_t msg_len) {
	tl->msg_start[msg_len] = '\n';
    return _send(logger, tl->msg_start, msg_len + 1);
}

static int
_fd_write_no_framing(struct logger *logger, struct logger_tl *tl, size_t msg_len) {
    return _write(logger, tl->msg_start, msg_len);
}

static int
_fd_write_oc_framing(struct logger *logger, struct logger_tl *tl, size_t msg_len) {
	char *buf = _render_size(tl, msg_len);
	int len = msg_len + (tl->msg_start - buf);
    return _write(logger, buf, len);
}

static int
_fd_write_nl_framing(struct logger *logger, struct logger_tl *tl, size_t msg_len) {
	tl->msg_start[msg_len] = '\n';
    return _write(logger, tl->msg_start, msg_len + 1);
}

static int
_inet_socket_connect(enum logger_protocol protocol, const char *addr, const char *service) {
	struct addrinfo hints, *res, *res0;
	int error;
	int s;
	const char *cause = NULL;
	int so;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = (protocol == LGR_TCP ? SOCK_STREAM : SOCK_DGRAM);
	error = getaddrinfo(addr, service, &hints, &res0);

	if (error)
		errx(1, "getaddrinfo(): %s", gai_strerror(error));

	s = -1;
	for (res = res0; res; res = res->ai_next) {
        s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s < 0) {
            cause = "socket()";
            continue;
        }

        if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
            cause = "connect()";
            close(s);
            s = -1;
            continue;
        }

        break;
	}
	freeaddrinfo(res0);

	if (s < 0) {
		warn("%s", cause);
		return -1;
	}

	so = 1;

#ifdef SO_REUSEPORT
    if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &so, sizeof(int)) == -1)
		err(1, "setsockopt()");
#endif

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &so, sizeof(int)) == -1)
		err(1, "setsockopt()");

    so = 1024*1024;
    if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &so, sizeof(int)) == -1)
		err(1, "setsockopt()");

	return s;
}

static int
_unix_socket_connect(enum logger_protocol protocol, const char *path, const char *service) {
	int s, so;
    struct sockaddr_un addr;

    addr.sun_family = AF_UNIX;
    strlcpy(addr.sun_path, path, sizeof(addr.sun_path));

	if ((s = socket(AF_UNIX, (protocol == LGR_UNIX_STREAM ? SOCK_STREAM : SOCK_DGRAM), 0)) == -1) {
		warn("socket()");
		return -1;
	}
	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        close(s);
		warn("connect()");
		return -1;
	}

    so = 1024*1024;
    if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &so, sizeof(int)) == -1)
		err(1, "setsockopt()");

    return s;
}

static int
_file_connect(enum logger_protocol protocol, const char *path, const char *service) {
	int fd = open(path, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (fd == -1)
		warn("open()");
	return fd;
}

static int
_stdout_connect(enum logger_protocol protocol, const char *addr, const char *service) {
	return STDOUT_FILENO;
}

static int
_stderr_connect(enum logger_protocol protocol, const char *addr, const char *service) {
	return STDERR_FILENO;
}

static int
_render_string_field(char *c, int r, char *v) {
	int n;
	if (v == NULL)
		v = "-";
	n = snprintf(c, r, "%s ", v);
	if (n < 0 || n > r)
		errx(1, "snprintf");
	return n;
}


static void
_prerender_size(struct logger_tl *tl) {
	memset(tl->buf, '0', MAX_LEN_LEN - 1);
	tl->buf[MAX_LEN_LEN - 1] = ' ';
	tl->msg_start = tl->buf + MAX_LEN_LEN;
}

static void
_skip_size(struct logger_tl *tl) {
	tl->msg_start = tl->buf;
}

static int
_prerender_pri(struct logger_tl *tl, int pri) {
	char *start = tl->msg_start;
	char *o;
	int n = snprintf(start, BUFFER_SIZE, "<%d>1 ", pri);
	if (n < 0 || n > BUFFER_SIZE)
		errx(1, "snprintf");
    o = tl->timestamp;
    tl->timestamp = start + n;
	tl->max_timestamp = BUFFER_SIZE - n;
    return o != tl->timestamp;
}

static int
_skip_pri(struct logger_tl *tl, int pri) {
	char *start = tl->msg_start;
    char *o = tl->timestamp;
    tl->timestamp = start;
	tl->max_timestamp = BUFFER_SIZE;
    return o != tl->timestamp;
}

static int
_render_timestamp(struct logger_tl *tl) {
	const time_t clock = time(NULL);
	struct tm result;
	char *o;
	size_t n;
	if (tl->last_clock == clock)
		return 0;

    gmtime_r(&clock, &result);

    tl->last_clock = clock;
    n = strftime(tl->timestamp, tl->max_timestamp, "%Y-%m-%dT%H:%M:%S%z ", &result);
    if (n == 0)
    	errx(1, "strftime");
    o = tl->meta;
    tl->meta = tl->timestamp + n;
	tl->max_meta = tl->max_timestamp - n;
    return o != tl->meta;
}

static int
_render_meta(struct logger *logger, struct logger_tl *tl) {
	int n = strlcpy(tl->meta,  logger->meta, tl->max_meta);
	char *o;
	if (n > tl->max_meta)
		errx(1, "strlcpy");
    o = tl->message;
	tl->message = tl->meta + n;
	tl->max_message = tl->max_meta - n;
    return o != tl->message;
}

static struct logger_tl*
_get_logger_tl(struct logger *logger) {
	const pthread_key_t key = logger->tl;
	struct logger_tl *tl = pthread_getspecific(key);
	if (tl == NULL) {
		tl = malloc(sizeof(struct logger_tl));
		memset(tl, 0, sizeof(struct logger_tl));
		switch (logger->config.framing) {
		case LGR_FRAMING_SYSLOG_NL:
		case LGR_FRAMING_SYSLOG:
		case LGR_FRAMING_NL:
			_skip_size(tl);
			break;
		case LGR_FRAMING_SYSLOG_OC:
			_prerender_size(tl);
			break;
		}

		switch (logger->config.framing) {
		case LGR_FRAMING_SYSLOG_NL:
		case LGR_FRAMING_SYSLOG:
		case LGR_FRAMING_SYSLOG_OC:
			_prerender_pri(tl, logger->pri);
			break;
		case LGR_FRAMING_NL:
			_skip_pri(tl, logger->pri);
			break;
		}

		_render_timestamp(tl);
		_render_meta(logger, tl);

		if (pthread_setspecific(key, tl))
			err(1, "pthread_setspecific");
	}
	return tl;
}

static void
_free_logger_tl(pthread_key_t key) {
	struct logger_tl *tl = pthread_getspecific(key);
	if (tl != NULL) {
		free(tl);
		if (pthread_setspecific(key, NULL))
			err(1, "pthread_setspecific");
	}
}

static int
_render_message(struct logger_tl *tl, const char *msg) {
	int n = strlcpy(tl->message, msg, tl->max_message);

    return tl->message - tl->msg_start + n;
}

static int
_render_messagef(struct logger_tl *tl, const char *fmt, va_list va_args) {
	int n = vsnprintf(tl->message, tl->max_message, fmt, va_args);

    return tl->message - tl->msg_start + n;
}


static void *
_connector(void *arg) {
	static struct timespec time_to_wait = {0, 0};
	struct logger *logger = (struct logger *) arg;
	struct logger_config config = logger->config;
	int fd;

	pthread_mutex_lock(&logger->connector_lock);
	while (logger->running) {
		time_to_wait.tv_sec = time(NULL) + 1;
        pthread_cond_timedwait(&logger->connector_cond, &logger->connector_lock, &time_to_wait);

		fd = logger->fd;
		if (fd == -1) {
			fd = logger->connect(config.protocol, config.address, config.port);
			if (fd != -1) {
				if (!__sync_bool_compare_and_swap(&logger->fd, -1, fd)) {
					close(fd);
				}
				else {
					if (pthread_cond_broadcast(&logger->connection_cond))
						err(1, "pthread_cond_broadcast()");
				}
			}
		}
	}
	pthread_mutex_unlock(&logger->connector_lock);
	return NULL;
}


static connect_fn
_connect_fn(enum logger_protocol protocol) {
	switch (protocol) {
	case LGR_FILE:
		return _file_connect;
	case LGR_STDOUT:
		return _stdout_connect;
	case LGR_STDERR:
		return _stderr_connect;
	case LGR_UNIX_STREAM:
	case LGR_UNIX_DGRAM:
		return _unix_socket_connect;
	case LGR_UDP:
	case LGR_TCP:
		return _inet_socket_connect;
	}
	errx(1, "Invalid protocol: %d", protocol);
}

static write_fn
_write_fn(enum logger_protocol protocol, enum logger_framing framing) {
	switch (protocol) {
	case LGR_FILE:
	case LGR_STDOUT:
	case LGR_STDERR:
	case LGR_UNIX_STREAM:
	case LGR_TCP:
		return WRITEFNS[WRITEFN_WRITE_OFFSET + framing];
	case LGR_UNIX_DGRAM:
	case LGR_UDP:
		return WRITEFNS[WRITEFN_SEND_OFFSET + framing];
	}
	errx(1, "Invalid protocol: %d", protocol);
}

static close_fn
_close_fn(enum logger_protocol protocol, enum logger_framing framing) {
	switch (protocol) {
	case LGR_STDOUT:
	case LGR_STDERR:
		return _close_fake;
	default:
		return _close_real;
	}
}

static void
_start_connector(struct logger *logger) {
    pthread_attr_t attr;
    if (pthread_attr_init(&attr))
    	err(1, "pthread_attr_init()");
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
    	err(1, "pthread_attr_setdetachstate()");
    if (pthread_mutex_init(&logger->connector_lock, NULL))
    	err(1, "pthread_mutex_init()");
    if (pthread_cond_init(&logger->connector_cond, NULL))
    	err(1, "pthread_cond_init()");
    if (pthread_cond_init(&logger->connection_cond, NULL))
    	err(1, "pthread_cond_init()");
    if (pthread_create(&logger->thread, NULL, _connector, logger))
    	err(1, "pthread_create()");
    if (pthread_attr_destroy(&attr))
    	err(1, "pthread_attr_destroy()");
}

void
logger_open(struct logger *logger, struct logger_config *config) {
	enum logger_framing framing = config->framing;
	enum logger_protocol protocol = config->protocol;
	logger->running = 1;
	logger->config = *config;
	logger->fd = -1;
	logger->connect = _connect_fn(protocol);
	logger->write = _write_fn(protocol, framing);
	logger->close = _close_fn(protocol, framing);
	logger->pri = (config->facility << 3) | config->severity;

	if (config->fields != NULL && config->fields[0] != NULL) {
		char *c = logger->meta;
		char **s;
		int n = 0;
		int r = 64;
		for (s = config->fields; *s != NULL; s++) {
			n = _render_string_field(c, r, *s);
			r -= n;
			c += n;
		}
	}
	else {
		logger->meta[0]=0;
	}
	if (pthread_key_create(&logger->tl, free))
		err(1, "pthread_key_create()");

	_start_connector(logger);
}

int
logger_log(struct logger *logger, const char *msg) {
	int len;
    struct logger_tl *tl = _get_logger_tl(logger);
    if (_render_timestamp(tl))
    	_render_meta(logger, tl);
    len = _render_message(tl, msg);

	return logger->write(logger, tl, len);
}

int
logger_render(struct logger *logger, render_fn renderer, void *arg) {
	int len;
    struct logger_tl *tl = _get_logger_tl(logger);
    if (_render_timestamp(tl))
    	_render_meta(logger, tl);
    len = (tl->message - tl->msg_start) + renderer(tl->message, tl->max_message, arg);

	return logger->write(logger, tl, len);
}

int
logger_logf(struct logger *logger, const char *fmt, ...) {
	int len;
    struct logger_tl *tl = _get_logger_tl(logger);
    va_list va_args;
    if (_render_timestamp(tl))
    	_render_meta(logger, tl);

	va_start(va_args, fmt);
    len = _render_messagef(tl, fmt, va_args);
	va_end(va_args);

	return logger->write(logger, tl, len);
}

void
logger_wait(struct logger *logger) {
	pthread_mutex_t lock;
	if (logger->fd != -1)
		return;

	pthread_mutex_init(&lock, NULL);
	pthread_mutex_lock(&lock);
	while (logger->running && (logger->fd == -1)) {
		pthread_cond_wait(&logger->connection_cond, &lock);
	}
	pthread_mutex_unlock(&lock);
	pthread_mutex_destroy(&lock);

}

void
logger_close(struct logger *logger) {
	_free_logger_tl(logger->tl);

	logger->running = 0;

	if (pthread_key_delete(logger->tl))
		err(1, "pthread_key_delete()");
	if (pthread_cond_signal(&logger->connector_cond))
		err(1, "pthread_cond_signal()");
	if (pthread_join(logger->thread, NULL))
		err(1, "pthread_join()");

	if (pthread_cond_destroy(&logger->connector_cond))
		err(1, "pthread_cond_destroy()");
	if (pthread_cond_destroy(&logger->connection_cond))
		err(1, "pthread_cond_destroy()");
	if (pthread_mutex_destroy(&logger->connector_lock))
		err(1, "pthread_mutex_destroy()");

	logger->close(logger, logger->fd);
}
