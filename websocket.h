/*
 * websocket.h -- tiny websocket library, need openssl.
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

/**
 *
 * http://www.rfc-editor.org/rfc/rfc6455.txt
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-------+-+-------------+-------------------------------+
 *    |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
 *    |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
 *    |N|V|V|V|       |S|             |   (if payload len==126/127)   |
 *    | |1|2|3|       |K|             |                               |
 *    +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
 *    |     Extended payload length continued, if payload len == 127  |
 *    + - - - - - - - - - - - - - - - +-------------------------------+
 *    |                               |Masking-key, if MASK set to 1  |
 *    +-------------------------------+-------------------------------+
 *    | Masking-key (continued)       |          Payload Data         |
 *    +-------------------------------- - - - - - - - - - - - - - - - +
 *    :                     Payload Data continued ...                :
 *    + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 *    |                     Payload Data continued ...                |
 *    +---------------------------------------------------------------+
 *
 *
 */

#ifndef _WEBSOCKET_H_
#define _WEBSOCKET_H_

#include <stddef.h>
#include <stdint.h>

#define WS_KEY_LEN 24
#define WS_ACCEPT_LEN 28
#define WS_SECRET_LEN 36

#define WS_MASK 13
#define WS_SECRET "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/** Websocket frame opcode. */
typedef enum {
    WS_OPCODE_CONTINUATION = 0x0,
    WS_OPCODE_TEXT = 0x1,
    WS_OPCODE_BINARY = 0x2,
    WS_OPCODE_CLOSE = 0x8,
    WS_OPCODE_PING = 0x9,
    WS_OPCODE_PONG = 0xa
} websocket_opcode_t;

/** Websocket frame flag.*/
#define WS_FLAG_FIN 0x10
#define WS_FLAG_MASK 0x20

/** Websocket close frame status. */
typedef enum {
    WS_STATUS_NORMAL = 1000,
    WS_STATUS_GOING_AWAY = 1001,
    WS_STATUS_PROTOCOL_ERROR = 1002,
    WS_STATUS_UNSUPPORTED_DATA_TYPE = 1003,
    WS_STATUS_STATUS_NOT_AVAILABLE = 1005,
    WS_STATUS_ABNORMAL_CLOSED = 1006,
    WS_STATUS_INVALID_PAYLOAD = 1007,
    WS_STATUS_POLICY_VIOLATION = 1008,
    WS_STATUS_MESSAGE_TOO_BIG = 1009,
    WS_STATUS_INVALID_EXTENSION = 1010,
    WS_STATUS_UNEXPECTED_CONDITION = 1011,
    WS_STATUS_TLS_HANDSHAKE_ERROR = 1015
} websocket_close_status_t;

/** Websocket request and response header flag. */
#define WS_HEADER_VERSION 0x01
#define WS_HEADER_UPGRADE 0x02
#define WS_HEADER_CONNECTION 0x04
#define WS_HEADER_KEY 0x08
#define WS_HEADER_ACCEPT 0x10
#define WS_HEADER_PROTOCOL 0x20

#define WS_HEADER_REQ (WS_HEADER_VERSION | WS_HEADER_UPGRADE | WS_HEADER_CONNECTION | WS_HEADER_KEY)

#define WS_HEADER_RSP (WS_HEADER_UPGRADE | WS_HEADER_CONNECTION | WS_HEADER_ACCEPT)

// help define
#define WS_CLOSE_STATUS(payload) ((((payload).data[0]) << 8) | (unsigned char)((payload).data[1]))
#define WS_CLOSE_REASON(payload) ((payload).data + 2)
#define WS_CLOSE_REASON_LEN(payload) ((int)(payload).length - 2)
#define WS_CLOSE_FRAME(payload, status, reason)      \
    do {                                             \
        payload[0] = (char)(status >> 8);            \
        payload[1] = (char)(status & 0xff);          \
        memcpy(payload + 2, reason, strlen(reason)); \
    } while (0)

#define WS_SWAP16(s) ((((s)&0xff) << 8) | (((s) >> 8) & 0xff))
#define WS_SWAP32(l) (((l) >> 24) | (((l)&0x00ff0000) >> 8) | (((l)&0x0000ff00) << 8) | ((l) << 24))
#define WS_SWAP64(ll)                                                                                          \
    (((ll) >> 56) | (((ll)&0x00ff000000000000) >> 40) | (((ll)&0x0000ff0000000000) >> 24) |                    \
     (((ll)&0x000000ff00000000) >> 8) | (((ll)&0x00000000ff000000) << 8) | (((ll)&0x0000000000ff0000) << 24) | \
     (((ll)&0x000000000000ff00) << 40) | (((ll) << 56)))

#define WS_BUILD_OPCODE(flags, op) (flags |= op)
#define WS_BUILD_FIN(flags) (flags |= WS_FLAG_FIN)
#define WS_BUILD_MASK(flags) (flags |= WS_FLAG_MASK)

typedef struct {
    char *data;
    uint64_t length;
} websocket_binary_t;

typedef struct {
    int fin;
    int mask;
    websocket_opcode_t opcode;
    websocket_binary_t payload;
} websocket_frame_t;

typedef struct {
    enum {
        WS_PARSER_START,
        WS_PARSER_HEAD,
        WS_PARSER_LENGTH,
        WS_PARSER_MASK,
        WS_PARSER_BODY,
    } state;

    uint64_t require;

    char mask[4];
    int flags;
    uint64_t mask_offset;
    uint64_t offset;
    uint64_t length;
} websocket_parser_t;

/**
 * calculate a websocket frame buff size with length payload
 * when a frame from c to s, mask = 1
 */
uint64_t websocket_build_size(int mask, uint64_t length);

/**
 * build a websocket frame into data
 *
 * flags:
 *      opcode - WS_BUILD_OPCODE()
 *         fin - WS_BUILD_FIN()
 *        mask - WS_BUILD_MASK()
 */
void websocket_build(char *data, int flags, websocket_binary_t *payload);

/**
 * initialize a websocket frame parser
 */
void websocket_parser_init(websocket_parser_t *parser);

/**
 * parse a websocket frame from b
 *
 * return:
 *      -1 - parse error
 *       0 - parse finish, need more data
 *       1 - a websocket frame parsed
 */
int websocket_parser_execute(websocket_parser_t *parser, websocket_binary_t *b, websocket_frame_t *f);

/**
 * initialize a websocket request
 */
int websocket_request(char *request, size_t len, const char *url, const char *host, const char *origin,
                      const char *protocol, char key[WS_KEY_LEN]);

/**
 * response a websocket resquest
 */
int websocket_response(char *response, size_t len, const char *server, const char *protocol, const char key[WS_KEY_LEN],
                       char accept[WS_ACCEPT_LEN]);

/**
 * check http request and response header for websocket
 * when request flags == WS_HEADER_REQ, when response flags == WS_HEADER_RSP
 * return header flag
 */
int websocket_valid_header(int *flags, const char *key, size_t key_len, const char *value, size_t value_len);

/**
 * generate a websocket request key
 */
void websocket_generate_key(char key[WS_KEY_LEN]);

/**
 * generate a websocket accept for response
 */
void websocket_generate_accept(char accept[WS_ACCEPT_LEN], const char key[WS_KEY_LEN]);

/**
 * check accept and key when handshake
 */
int websocket_handshake(const char key[WS_KEY_LEN], const char accept[WS_ACCEPT_LEN]);

#ifdef WSHTTP

#define WSHTTP_MAX_HTTP_LEN 4096
#define WSHTTP_MAX_PROTOCOL_LEN 16
#define WSHTTP_DEF_SERVER "websocket@zhoukk"

typedef struct wshttp_s wshttp_t;

typedef int wshttp_io_write_pt(wshttp_t *wh, void *io, void *ud, const char *data, int size);

typedef void wshttp_on_open_pt(wshttp_t *wh, void *io, void *ud);
typedef void wshttp_on_data_pt(wshttp_t *wh, void *io, void *ud, int opcode, websocket_binary_t payload);
typedef void wshttp_on_close_pt(wshttp_t *wh, void *io, void *ud, websocket_binary_t payload);

typedef struct {
    enum { WS_MODE_SERVER, WS_MODE_CLIENT } mode;
    wshttp_on_open_pt *on_open;
    wshttp_on_data_pt *on_data;
    wshttp_on_close_pt *on_close;

    void *io;
    wshttp_io_write_pt *write;

    void *ud;
} wshttp_config_t;

wshttp_t *wshttp_create(wshttp_config_t *config);

void wshttp_destroy(wshttp_t *wh);

int wshttp_feed(wshttp_t *wh, websocket_binary_t *b);

int wshttp_request(wshttp_t *wh, const char *url, const char *host, const char *protocol);

int wshttp_write(wshttp_t *wh, websocket_opcode_t opcode, websocket_binary_t *payload);

void wshttp_close(wshttp_t *wh, websocket_close_status_t close_status, const char *reason);

#endif // WSHTTP

#endif // _WEBSOCKET_H_

#ifdef WEBSOCKET_IMPL

/**
 * Implement
 */

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <assert.h>
#include <ctype.h>
#include <string.h>

static const unsigned char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *
strncasestr(const char *haystack, const char *needle, size_t len) {
    char c;

    if ((c = *needle++) != '\0') {
        size_t slen = strlen(needle);
        do {
            char sc;
            do {
                if (len-- < 1 || (sc = *haystack++) == '\0')
                    return 0;
            } while (tolower(sc) != tolower(c));
            if (slen > len)
                return 0;
        } while (strncasecmp(haystack, needle, slen) != 0);
        haystack--;
    }
    return (char *)haystack;
}

static uint64_t
frame_mask(char *buff, char mask[4], const char *payload, uint64_t length, uint64_t offset) {
    uint64_t i;
    for (i = 0; i < length; i++)
        buff[i] = payload[i] ^ mask[(i + offset) % 4];
    return ((i + offset) % 4);
}

uint64_t
websocket_build_size(int mask, uint64_t length) {
    return 2 + length + (mask ? 4 : 0) + (length >= 0x7e ? (length > 0xffff ? 8 : 2) : 0);
}

void
websocket_build(char *data, int flags, websocket_binary_t *payload) {
    int offset;
    uint32_t mask = WS_MASK;
    uint64_t length = payload->length;

    data[0] = 0;
    data[1] = 0;
    if (flags & WS_FLAG_FIN)
        data[0] = (char)(1 << 7);
    data[0] |= (char)(flags & 0xf);
    if (flags & WS_FLAG_MASK)
        data[1] = (char)(1 << 7);
    if (length < 0x7e) {
        data[1] |= (char)length;
        offset = 2;
    } else if (length <= 0xffff) {
        data[1] |= 0x7e;
        data[2] = (char)(length >> 8);
        data[3] = (char)(length & 0xff);
        offset = 4;
    } else {
        data[1] |= 0x7f;
        data[2] = (char)((length >> 56) & 0xff);
        data[3] = (char)((length >> 48) & 0xff);
        data[4] = (char)((length >> 40) & 0xff);
        data[5] = (char)((length >> 32) & 0xff);
        data[6] = (char)((length >> 24) & 0xff);
        data[7] = (char)((length >> 16) & 0xff);
        data[8] = (char)((length >> 8) & 0xff);
        data[9] = (char)((length >> 0) & 0xff);
        offset = 10;
    }
    if (flags & WS_FLAG_MASK) {
        memcpy(&data[offset], &mask, 4);
        offset += 4;
        if (payload->data && length)
            frame_mask(&data[offset], (char *)&mask, payload->data, length, 0);
    } else if (payload->data && length)
        memcpy(&data[offset], payload->data, length);
}

void
websocket_parser_init(websocket_parser_t *parser) {
    memset(parser, 0, sizeof *parser);
    parser->state = WS_PARSER_START;
}

int
websocket_parser_execute(websocket_parser_t *parser, websocket_binary_t *b, websocket_frame_t *f) {
    char *s = b->data;
    char *e = b->data + b->length;
    uint64_t offset = 0;

    while (s < e) {
        switch (parser->state) {
        case WS_PARSER_START:
            parser->offset = 0;
            parser->length = 0;
            parser->mask_offset = 0;
            parser->flags = ((*s) & 0xf);
            if ((*s) & (1 << 7))
                parser->flags |= WS_FLAG_FIN;
            parser->state = WS_PARSER_HEAD;
            offset++;
            s++;
            break;
        case WS_PARSER_HEAD:
            parser->length = (*s) & 0x7f;
            if ((*s) & 0x80)
                parser->flags |= WS_FLAG_MASK;
            if (parser->length >= 0x7e) {
                if (parser->length == 0x7f)
                    parser->require = 8;
                else
                    parser->require = 2;
                parser->length = 0;
                parser->state = WS_PARSER_LENGTH;
            } else if (parser->flags & WS_FLAG_MASK) {
                parser->state = WS_PARSER_MASK;
                parser->require = 4;
            } else if (parser->length) {
                parser->state = WS_PARSER_BODY;
                parser->require = parser->length;
                f->opcode = parser->flags & 0xf;
                f->fin = !!(parser->flags & 0x10);
                f->mask = !!(parser->flags & 0x20);
                f->payload.length = parser->length;
                f->payload.data = (char *)malloc(parser->length);
            } else {
                parser->state = WS_PARSER_START;
                f->opcode = parser->flags & 0xf;
                f->fin = !!(parser->flags & 0x10);
                f->mask = !!(parser->flags & 0x20);
                f->payload.length = parser->length;
                f->payload.data = 0;
                b->length = e - s;
                b->data = s;
                return 1;
            }
            offset++;
            s++;
            break;
        case WS_PARSER_LENGTH:
            while (s < e && parser->require) {
                parser->length <<= 8;
                parser->length |= (unsigned char)(*s);
                parser->require--;
                offset++;
                s++;
            }
            if (!parser->require) {
                if (parser->flags & WS_FLAG_MASK) {
                    parser->state = WS_PARSER_MASK;
                    parser->require = 4;
                } else if (parser->length) {
                    parser->state = WS_PARSER_BODY;
                    parser->require = parser->length;
                    f->opcode = parser->flags & 0xf;
                    f->fin = !!(parser->flags & 0x10);
                    f->mask = !!(parser->flags & 0x20);
                    f->payload.length = parser->length;
                    f->payload.data = (char *)malloc(parser->length);
                } else {
                    parser->state = WS_PARSER_START;
                    f->opcode = parser->flags & 0xf;
                    f->fin = !!(parser->flags & 0x10);
                    f->mask = !!(parser->flags & 0x20);
                    f->payload.length = parser->length;
                    f->payload.data = 0;
                    b->length = e - s;
                    b->data = s;
                    return 1;
                }
            }
            break;
        case WS_PARSER_MASK:
            while (s < e && parser->require) {
                parser->mask[4 - parser->require--] = *s;
                offset++;
                s++;
            }
            if (!parser->require) {
                if (parser->length) {
                    parser->state = WS_PARSER_BODY;
                    parser->require = parser->length;
                    f->opcode = parser->flags & 0xf;
                    f->fin = !!(parser->flags & 0x10);
                    f->mask = !!(parser->flags & 0x20);
                    f->payload.length = parser->length;
                    f->payload.data = (char *)malloc(parser->length);
                } else {
                    parser->state = WS_PARSER_START;
                    f->opcode = parser->flags & 0xf;
                    f->fin = !!(parser->flags & 0x10);
                    f->mask = !!(parser->flags & 0x20);
                    f->payload.length = parser->length;
                    f->payload.data = 0;
                    b->length = e - s;
                    b->data = s;
                    return 1;
                }
            }
            break;
        case WS_PARSER_BODY:
            if (parser->require) {
                if (s + parser->require <= e) {
                    parser->mask_offset = frame_mask(f->payload.data + parser->offset, parser->mask, s, parser->require,
                                                     parser->mask_offset);
                    s += parser->require;
                    parser->require = 0;
                    offset = s - b->data;
                } else {
                    parser->mask_offset = frame_mask(f->payload.data + parser->offset, parser->mask, s,
                                                     (uint64_t)(e - s), parser->mask_offset);
                    parser->require -= (uint64_t)(e - s);
                    s = e;
                    parser->offset += (uint64_t)(s - b->data - offset);
                    offset = 0;
                }
            }
            if (!parser->require) {
                parser->state = WS_PARSER_START;
                f->opcode = parser->flags & 0xf;
                f->fin = !!(parser->flags & 0x10);
                f->mask = !!(parser->flags & 0x20);
                f->payload.length = parser->length;
                b->length = e - s;
                b->data = s;
                return 1;
            }
            break;
        }
    }
    return 0;
}

void
websocket_generate_key(char key[WS_KEY_LEN]) {
    unsigned char randkey[16];
    unsigned char _key[WS_KEY_LEN + 1];
    int i, n;

    for (i = 0; i < 16; i++) {
        randkey[i] = b64[(rand() + time(0)) % 61];
    }
    n = EVP_EncodeBlock(_key, randkey, 16);
    assert(n == WS_KEY_LEN);
    memcpy(key, (char *)_key, WS_KEY_LEN);
}

void
websocket_generate_accept(char accept[WS_ACCEPT_LEN], const char key[WS_KEY_LEN]) {
    int n;
    unsigned char buff[WS_KEY_LEN + WS_SECRET_LEN];
    unsigned char _accept[WS_ACCEPT_LEN + 1];
    unsigned char digest[SHA_DIGEST_LENGTH];

    memcpy(buff, key, WS_KEY_LEN);
    memcpy(buff + WS_KEY_LEN, WS_SECRET, WS_SECRET_LEN);
    SHA1(buff, (size_t)(WS_KEY_LEN + WS_SECRET_LEN), digest);
    n = EVP_EncodeBlock(_accept, digest, SHA_DIGEST_LENGTH);
    assert(n == WS_ACCEPT_LEN);
    memcpy(accept, (char *)_accept, WS_ACCEPT_LEN);
}

int
websocket_request(char *request, size_t len, const char *url, const char *host, const char *origin,
                  const char *protocol, char key[WS_KEY_LEN]) {
    websocket_generate_key(key);

    if (protocol && protocol[0] != '\0') {
        const char *fmt = "GET %s HTTP/1.1\r\n"
                          "Host: %s\r\n"
                          "Origin: %s\r\n"
                          "Upgrade: websocket\r\n"
                          "Connection: Upgrade\r\n"
                          "Sec-WebSocket-Key: %.*s\r\n"
                          "Sec-WebSocket-Protocol: %s\r\n"
                          "Sec-WebSocket-Version: 13\r\n"
                          "\r\n";
        return snprintf(request, len, fmt, url, host, origin, WS_KEY_LEN, key, protocol);
    } else {
        const char *fmt = "GET %s HTTP/1.1\r\n"
                          "Host: %s\r\n"
                          "Origin: %s\r\n"
                          "Upgrade: websocket\r\n"
                          "Connection: Upgrade\r\n"
                          "Sec-WebSocket-Key: %.*s\r\n"
                          "Sec-WebSocket-Version: 13\r\n"
                          "\r\n";
        return snprintf(request, len, fmt, url, host, origin, WS_KEY_LEN, key);
    }
}

int
websocket_response(char *response, size_t len, const char *server, const char *protocol, const char key[WS_KEY_LEN],
                   char accept[WS_ACCEPT_LEN]) {
    websocket_generate_accept(accept, key);

    if (protocol && protocol[0] != '\0') {
        const char *fmt = "HTTP/1.1 101 Switching Protocols\r\n"
                          "Server: %s\r\n"
                          "Upgrade: websocket\r\n"
                          "Connection: Upgrade\r\n"
                          "Sec-WebSocket-Accept: %.*s\r\n"
                          "Sec-WebSocket-Protocol: %s\r\n"
                          "\r\n";
        return snprintf(response, len, fmt, server, WS_ACCEPT_LEN, accept, protocol);
    } else {
        const char *fmt = "HTTP/1.1 101 Switching Protocols\r\n"
                          "Server: %s\r\n"
                          "Upgrade: websocket\r\n"
                          "Connection: Upgrade\r\n"
                          "Sec-WebSocket-Accept: %.*s\r\n"
                          "\r\n";
        return snprintf(response, len, fmt, server, WS_ACCEPT_LEN, accept);
    }
}

int
websocket_handshake(const char key[WS_KEY_LEN], const char accept[WS_ACCEPT_LEN]) {
    char check_accept[WS_ACCEPT_LEN];
    websocket_generate_accept(check_accept, key);
    return 0 == strncmp(check_accept, accept, WS_ACCEPT_LEN) ? 0 : -1;
}

int
websocket_valid_header(int *flags, const char *key, size_t key_len, const char *value, size_t value_len) {
    if (!key || !value)
        return 0;

    if (0 == strncasecmp(key, "Sec-WebSocket-Version", key_len)) {
        if (0 == strncmp(value, "13", value_len)) {
            *flags |= WS_HEADER_VERSION;
            return WS_HEADER_VERSION;
        } else
            *flags &= ~WS_HEADER_VERSION;
    } else if (0 == strncasecmp(key, "Upgrade", key_len)) {
        if (0 == strncasecmp(value, "websocket", value_len)) {
            *flags |= WS_HEADER_UPGRADE;
            return WS_HEADER_UPGRADE;
        } else
            *flags &= ~WS_HEADER_UPGRADE;
    } else if (0 == strncasecmp(key, "Connection", key_len)) {
        if (strncasestr(value, "Upgrade", value_len)) {
            *flags |= WS_HEADER_CONNECTION;
            return WS_HEADER_CONNECTION;
        } else
            *flags &= ~WS_HEADER_CONNECTION;
    } else if (0 == strncasecmp(key, "Sec-WebSocket-Key", key_len)) {
        if (value_len == WS_KEY_LEN) {
            *flags |= WS_HEADER_KEY;
            return WS_HEADER_KEY;
        } else
            *flags &= ~WS_HEADER_KEY;
    } else if (0 == strncasecmp(key, "Sec-WebSocket-Accept", key_len)) {
        if (value_len == WS_ACCEPT_LEN) {
            *flags |= WS_HEADER_ACCEPT;
            return WS_HEADER_ACCEPT;
        } else
            *flags &= ~WS_HEADER_ACCEPT;
    } else if (0 == strncasecmp(key, "Sec-WebSocket-Protocol", key_len)) {
        return WS_HEADER_PROTOCOL;
    }
    return 0;
}

#ifdef WSHTTP

#include "http_parser.h"

struct wshttp_s {
    int handshake;

    http_parser http_p;
    websocket_parser_t ws_p;

    char key[WS_KEY_LEN];
    char accept[WS_ACCEPT_LEN];
    char protocol[WSHTTP_MAX_PROTOCOL_LEN];

    const char *header_at;
    size_t header_length;

    int flags;

    wshttp_config_t config;
};

static int
__on_message_begin(http_parser *p) {
    (void)p;
    return 0;
}

static int
__on_url(http_parser *p, const char *at, size_t length) {
    (void)p;
    (void)at;
    (void)length;
    return 0;
}

static int
__on_status(http_parser *p, const char *at, size_t length) {
    (void)p;
    (void)at;
    (void)length;
    return 0;
}

static int
__on_header_field(http_parser *p, const char *at, size_t length) {
    wshttp_t *wh = (wshttp_t *)p->data;
    wh->header_at = at;
    wh->header_length = length;
    return 0;
}

static int
__on_header_value(http_parser *p, const char *at, size_t length) {
    wshttp_t *wh = (wshttp_t *)p->data;
    int flag = websocket_valid_header(&wh->flags, wh->header_at, wh->header_length, at, length);
    if (flag == WS_HEADER_KEY) {
        strncpy(wh->key, at, length);
    } else if (flag == WS_HEADER_ACCEPT) {
        strncpy(wh->accept, at, length);
    } else if (flag == WS_HEADER_PROTOCOL) {
        int n = length < WSHTTP_MAX_PROTOCOL_LEN ? length : WSHTTP_MAX_PROTOCOL_LEN;
        strncpy(wh->protocol, at, n);
    }
    return 0;
}

static int
__on_headers_complete(http_parser *p) {
    wshttp_t *wh = (wshttp_t *)p->data;
    if (wh->flags != (wh->config.mode == WS_MODE_SERVER ? WS_HEADER_REQ : WS_HEADER_RSP)) {
        return -1;
    }
    return 0;
}

static int
__on_body(http_parser *p, const char *at, size_t length) {
    (void)p;
    (void)at;
    (void)length;
    return 0;
}

static int
__on_message_complete(http_parser *p) {
    wshttp_t *wh = (wshttp_t *)p->data;
    if (wh->config.mode == WS_MODE_SERVER) {
        char response[WSHTTP_MAX_HTTP_LEN];
        int n = websocket_response(response, WSHTTP_MAX_HTTP_LEN, WSHTTP_DEF_SERVER, wh->protocol, wh->key, wh->accept);
        if (wh->config.write(wh, wh->config.io, wh->config.ud, response, n)) {
            return -1;
        } else {
            wh->handshake = 1;
        }
    } else {
        if (!websocket_handshake(wh->key, wh->accept)) {
            wh->handshake = 1;
        } else {
            return -1;
        }
    }
    return 0;
}

wshttp_t *
wshttp_create(wshttp_config_t *config) {
    wshttp_t *wh;

    wh = (wshttp_t *)malloc(sizeof *wh);
    memset(wh, 0, sizeof *wh);

    wh->config = *config;
    http_parser_init(&wh->http_p, config->mode == WS_MODE_SERVER ? HTTP_REQUEST : HTTP_RESPONSE);
    wh->http_p.data = wh;
    websocket_parser_init(&wh->ws_p);
    wh->config.ud = config->ud;

    return wh;
}

int
wshttp_request(wshttp_t *wh, const char *url, const char *host, const char *protocol) {
    char request[WSHTTP_MAX_HTTP_LEN];
    int n = websocket_request(request, WSHTTP_MAX_HTTP_LEN, url, host, host, protocol, wh->key);
    return wh->config.write(wh, wh->config.io, wh->config.ud, request, n);
}

int
wshttp_feed(wshttp_t *wh, websocket_binary_t *b) {
    static http_parser_settings settings = {
        .on_message_begin = __on_message_begin,
        .on_url = __on_url,
        .on_status = __on_status,
        .on_header_field = __on_header_field,
        .on_header_value = __on_header_value,
        .on_headers_complete = __on_headers_complete,
        .on_body = __on_body,
        .on_message_complete = __on_message_complete,
    };

    if (b->length == 0)
        return 0;

    if (!wh->handshake) {
        int parsed = http_parser_execute(&wh->http_p, &settings, b->data, b->length);
        if (wh->http_p.http_errno) {
            fprintf(stderr, "http_parser_execute: %s %s\n", http_errno_name(wh->http_p.http_errno),
                    http_errno_description(wh->http_p.http_errno));
            return -1;
        }
        b->length -= parsed;
        b->data += parsed;
        if (wh->handshake) {
            wh->config.on_open(wh, wh->config.io, wh->config.ud);
        }
    } else {
        websocket_frame_t f;

        do {
            int rc = websocket_parser_execute(&wh->ws_p, b, &f);
            if (rc <= 0) {
                return rc;
            }
            if (f.opcode == WS_OPCODE_PING) {
                websocket_binary_t dummy = {0, 0};
                wshttp_write(wh, WS_OPCODE_PONG, &dummy);
                return 0;
            }
            if (f.opcode == WS_OPCODE_CLOSE) {
                wh->config.on_close(wh, wh->config.io, wh->config.ud, f.payload);
            } else {
                wh->config.on_data(wh, wh->config.io, wh->config.ud, f.opcode, f.payload);
            }
            if (f.payload.data && f.payload.length)
                free(f.payload.data);
        } while (1);
    }
    return 0;
}

int
wshttp_write(wshttp_t *wh, websocket_opcode_t opcode, websocket_binary_t *payload) {
    char *data;
    uint64_t size;
    int flags = 0;
    int rc;

    size = websocket_build_size(wh->config.mode == WS_MODE_CLIENT, payload->length);
    data = (char *)malloc(size);
    WS_BUILD_OPCODE(flags, opcode);
    WS_BUILD_FIN(flags);
    if (wh->config.mode == WS_MODE_CLIENT)
        WS_BUILD_MASK(flags);
    websocket_build(data, flags, payload);
    rc = wh->config.write(wh, wh->config.io, wh->config.ud, data, size);
    free(data);
    return rc;
}

void
wshttp_close(wshttp_t *wh, websocket_close_status_t close_status, const char *reason) {
    websocket_binary_t b;
    size_t len = strlen(reason);
    char payload[2 + len];
    uint16_t s = (uint16_t)((close_status & 0xff00) >> 8 | (close_status & 0xff) << 8);
    char *p = (char *)&s;
    memcpy(payload, p, sizeof s);
    memcpy(payload + sizeof s, reason, len);
    b.data = payload;
    b.length = len + 2;

    wshttp_write(wh, WS_OPCODE_CLOSE, &b);
}

void
wshttp_destroy(wshttp_t *wh) {
    free(wh);
}

#endif // WSHTTP

#endif /* WEBSOCKET_IMPL */
