/*
 * log.h -- log library.
 *
 * Copyright (c) zhoukk <izhoukk@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _LOG_H_
#define _LOG_H_

#include <inttypes.h>

// XXX(id, str)
#define LOG_LEVEL_MAP(XXX)        \
    XXX(LOG_LEVEL_DEBUG, "DEBUG") \
    XXX(LOG_LEVEL_INFO, "INFO ")  \
    XXX(LOG_LEVEL_WARN, "WARN ")  \
    XXX(LOG_LEVEL_ERROR, "ERROR")

typedef enum {
#define XXX(id, str) id,
    LOG_LEVEL_MAP(XXX)
#undef XXX
} log_level_e;

#define DEFAULT_LOG_LEVEL LOG_LEVEL_DEBUG
#define DEFAULT_LOG_MAX_BUFSIZE (1 << 12) // 4k

typedef void (*logger_handler_pt)(log_level_e level, const char *buf, int len);

typedef struct logger_s logger_t;

logger_t *logger_create();
void logger_destroy(logger_t *logger);
logger_t *logger_default();

void logger_set_level(logger_t *logger, log_level_e level);
void logger_set_handler(logger_t *logger, logger_handler_pt handler);
void logger_set_file(logger_t *logger, const char *filename);

void logger_update(logger_t *logger, uint64_t time);
void logger_print(logger_t *logger, log_level_e level, const char *fmt, ...);

#define LOG_SET_HANDLER(handler) logger_set_handler(logger_default(), handler)
#define LOG_SET_LEVEL(level) logger_set_level(logger_default(), level)
#define LOG_SET_FILE(filename) logger_set_file(logger_default(), filename)
#define LOG_UPDATE(time) logger_update(logger_default(), time)

#define LOG_D(fmt, ...)                                                                                     \
    logger_print(logger_default(), LOG_LEVEL_DEBUG, fmt " [%s:%d:%s]\n", ##__VA_ARGS__, __FILE__, __LINE__, \
                 __FUNCTION__)
#define LOG_I(fmt, ...) logger_print(logger_default(), LOG_LEVEL_INFO, fmt "\n", ##__VA_ARGS__)
#define LOG_W(fmt, ...) \
    logger_print(logger_default(), LOG_LEVEL_WARN, fmt " [%s:%d:%s]\n", ##__VA_ARGS__, __FILE__, __LINE__, __FUNCTION__)
#define LOG_E(fmt, ...)                                                                                     \
    logger_print(logger_default(), LOG_LEVEL_ERROR, fmt " [%s:%d:%s]\n", ##__VA_ARGS__, __FILE__, __LINE__, \
                 __FUNCTION__)

#endif /* _LOG_H_ */

#ifdef LOG_IMPL

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct logger_s {
    char *buf;
    log_level_e level;
    FILE *logf;
    uint64_t time;
    logger_handler_pt handler;
};

logger_t *
logger_create() {
    logger_t *logger;

    logger = (logger_t *)malloc(sizeof *logger);
    memset(logger, 0, sizeof *logger);

    logger->buf = (char *)malloc(DEFAULT_LOG_MAX_BUFSIZE);
    logger->level = DEFAULT_LOG_LEVEL;
    logger->logf = stdout;

    return logger;
}

void
logger_destroy(logger_t *logger) {
    if (logger) {
        if (logger->buf) {
            free(logger->buf);
        }
        if (logger->logf != stdout) {
            fclose(logger->logf);
        }
        free(logger);
    }
}

logger_t *
logger_default() {
    static logger_t *s_logger = 0;
    if (!s_logger) {
        s_logger = logger_create();
    }
    return s_logger;
}

void
logger_set_level(logger_t *logger, log_level_e level) {
    logger->level = level;
}

void
logger_set_handler(logger_t *logger, logger_handler_pt handler) {
    logger->handler = handler;
}

void
logger_set_file(logger_t *logger, const char *filename) {
    FILE *f;

    f = fopen(filename, "a");
    if (f) {
        logger->logf = f;
    }
}

void
logger_update(logger_t *logger, uint64_t time) {
    logger->time = time;
}

void
logger_print(logger_t *logger, log_level_e level, const char *fmt, ...) {
    char *buf;
    int bufsize, len;
    const char *level_str = "";

    if (level < logger->level) {
        return;
    }

#define XXX(id, str)     \
    case id:             \
        level_str = str; \
        break;

    switch (level) { LOG_LEVEL_MAP(XXX) }
#undef XXX

    buf = logger->buf;
    bufsize = DEFAULT_LOG_MAX_BUFSIZE;
    len = snprintf(buf, bufsize, "[%" PRIu64 "] [%s] ", logger->time, level_str);

    va_list ap;
    va_start(ap, fmt);
    len += vsnprintf(buf + len, bufsize - len, fmt, ap);
    va_end(ap);

    if (logger->handler) {
        logger->handler(level, buf, len);
    } else {
        fprintf(logger->logf, "%.*s", len, buf);
        fflush(logger->logf);
    }
}

#endif /* LOG_IMPL */
