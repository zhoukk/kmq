/*
 * http.h -- http library.
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

#ifndef _HTTP_H_
#define _HTTP_H_

#include "http_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *s;
    size_t n;
} http_str_t;

typedef struct http_param_s http_param_t;

struct http_param_s {
    char *key;
    char *val;

    http_param_t *next;
};

typedef struct {
    char *schema;
    char *host;
    int port;
    char *path;
    char *fragment;
    char *userinfo;
    struct {
        http_param_t *head;
        http_param_t *tail;
    } params;
} http_url_t;

typedef struct http_header_s http_header_t;

struct http_header_s {
    char *field;
    char *value;

    http_header_t *next;
};

typedef struct {
    http_header_t *head;
    http_header_t *tail;
} http_headers_t;

typedef struct {
    const char *method;
    http_url_t url;
    http_headers_t headers;
    http_str_t body;

    struct {
        int complete;
        http_parser parser;
        const char *field_at;
        size_t field_length;
    } p;
} http_request_t;

typedef struct {
    int status;
    http_headers_t headers;
    http_str_t body;

    struct {
        int complete;
        http_parser parser;
        const char *field_at;
        size_t field_length;
    } p;
} http_response_t;

static inline void
http_str_free(http_str_t *str) {
    if (str->s && str->n) {
        free(str->s);
    }
    str->s = 0;
    str->n = 0;
}

void http_url_set_schema(http_url_t *url, const char *schema);
void http_url_set_host(http_url_t *url, const char *host);
void http_url_set_port(http_url_t *url, int port);
void http_url_set_path(http_url_t *url, const char *path);
void http_url_set_param(http_url_t *url, const char *key, const char *val);
void http_url_set_fragment(http_url_t *url, const char *fragment);
void http_url_set_userinfo(http_url_t *url, const char *userinfo);
const char *http_url_schema(http_url_t *url);
const char *http_url_host(http_url_t *url);
int http_url_port(http_url_t *url);
const char *http_url_path(http_url_t *url);
const char *http_url_param(http_url_t *url, const char *key);
const char *http_url_fragment(http_url_t *url);
const char *http_url_userinfo(http_url_t *url);
int http_url_build(http_url_t *url, char *s);
int http_url_parse(http_url_t *url, const char *s);

void http_request_init(http_request_t *req);
void http_request_unit(http_request_t *req);
void http_request_set_method(http_request_t *req, const char *method);
void http_request_set_header(http_request_t *req, const char *field, const char *value);
void http_request_set_body(http_request_t *req, http_str_t body);
const char *http_request_method(http_request_t *req);
http_url_t *http_request_url(http_request_t *req);
const char *http_request_header(http_request_t *req, const char *field);
http_str_t http_request_body(http_request_t *req);
http_str_t http_request_build(http_request_t *req);
int http_request_parse(http_request_t *req, http_str_t buf);

void http_response_init(http_response_t *res);
void http_response_unit(http_response_t *res);
void http_response_set_status(http_response_t *res, int status);
void http_response_set_header(http_response_t *res, const char *field, const char *value);
void http_response_set_body(http_response_t *res, http_str_t body);
int http_response_status(http_response_t *res);
const char *http_response_header(http_response_t *res, const char *field);
http_str_t http_response_body(http_response_t *res);
http_str_t http_response_build(http_response_t *res);
int http_response_parse(http_response_t *res, http_str_t buf);

#endif // _HTTP_H_

#ifdef HTTP_IMPL

/**
 * Implement
 */

#include "base64.h"
#include "urlcode.h"

static void
__param_clear(http_url_t *url) {
    http_param_t *p;

    p = url->params.head;
    while (p) {
        http_param_t *next;

        next = p->next;
        if (p->key)
            free(p->key);
        if (p->val)
            free(p->val);
        free(p);
        p = next;
    }
    url->params.head = url->params.tail = 0;
}

static void
__url_clear(http_url_t *url) {
    if (url->schema)
        free(url->schema);
    if (url->host)
        free(url->host);
    if (url->path)
        free(url->path);
    if (url->fragment)
        free(url->fragment);
    if (url->userinfo)
        free(url->userinfo);
    __param_clear(url);
    memset(url, 0, sizeof *url);
}

static void
__headers_set(http_headers_t *headers, const char *field, const char *value) {
    http_header_t *header;

    header = headers->head;
    while (header) {
        if (0 == strcasecmp(header->field, field)) {
            if (header->value) {
                free(header->value);
                header->value = 0;
            }
            if (value)
                header->value = strdup(value);
            return;
        }
        header = header->next;
    }

    if (!value)
        return;
    header = (http_header_t *)malloc(sizeof *header);
    memset(header, 0, sizeof *header);

    header->field = strdup(field);
    header->value = strdup(value);
    if (headers->head == 0) {
        headers->head = headers->tail = header;
    } else {
        headers->tail->next = header;
        headers->tail = header;
    }
}

static const char *
__headers_get(http_headers_t *headers, const char *field) {
    http_header_t *header;

    header = headers->head;
    while (header) {
        if (0 == strcasecmp(header->field, field)) {
            return header->value;
        }
        header = header->next;
    }
    return 0;
}

static void
__headers_clear(http_headers_t *headers) {
    http_header_t *header;

    header = headers->head;
    while (header) {
        http_header_t *next;

        next = header->next;
        if (header->field)
            free(header->field);
        if (header->value)
            free(header->value);
        free(header);
        header = next;
    }
    headers->head = headers->tail = 0;
}

void
http_url_set_schema(http_url_t *url, const char *schema) {
    if (url->schema)
        free(url->schema);
    url->schema = strdup(schema);
}

void
http_url_set_host(http_url_t *url, const char *host) {
    if (url->host)
        free(url->host);
    url->host = strdup(host);
}

void
http_url_set_port(http_url_t *url, int port) {
    url->port = port;
}

void
http_url_set_path(http_url_t *url, const char *path) {
    if (url->path)
        free(url->path);
    url->path = strdup(path);
}

static void
__param_parse(http_url_t *url, const char *query) {
    char str[strlen(query) + 1];
    char *p;

    strcpy(str, query);
    p = str;
    while (p && *p != '\0') {
        char *key, *val;
        http_param_t *param;

        val = strsep(&p, "&");
        key = strsep(&val, "=");
        if (!val || *key == '\0') {
            break;
        }

        char deval[strlen(val) + 1];
        url_decode(val, strlen(val), deval);
        param = (http_param_t *)malloc(sizeof *param);
        memset(param, 0, sizeof *param);
        param->key = strdup(key);
        param->val = strdup(deval);
        if (!url->params.head) {
            url->params.head = url->params.tail = param;
        } else {
            url->params.tail->next = param;
            url->params.tail = param;
        }
    }
}

void
http_url_set_param(http_url_t *url, const char *key, const char *val) {
    http_param_t *p;

    if (!key || !val || !key[0] || !val[0])
        return;
    p = url->params.head;
    while (p) {
        if (0 == strcasecmp(p->key, key)) {
            if (p->val)
                free(p->val);
            p->val = strdup(val);
            return;
        }
        p = p->next;
    }

    p = (http_param_t *)malloc(sizeof *p);
    memset(p, 0, sizeof *p);
    p->key = strdup(key);
    p->val = strdup(val);
    if (!url->params.head) {
        url->params.head = url->params.tail = p;
    } else {
        url->params.tail->next = p;
        url->params.tail = p;
    }
}

void
http_url_set_fragment(http_url_t *url, const char *fragment) {
    if (url->fragment)
        free(url->fragment);
    url->fragment = strdup(fragment);
}

void
http_url_set_userinfo(http_url_t *url, const char *userinfo) {
    if (url->userinfo)
        free(url->userinfo);
    url->userinfo = strdup(userinfo);
}

const char *
http_url_schema(http_url_t *url) {
    return url->schema ? url->schema : "http";
}

const char *
http_url_host(http_url_t *url) {
    return url->host;
}

int
http_url_port(http_url_t *url) {
    return url->port > 0 ? url->port : 80;
}

const char *
http_url_path(http_url_t *url) {
    return url->path;
}

const char *
http_url_param(http_url_t *url, const char *key) {
    http_param_t *p;

    p = url->params.head;
    while (p) {
        if (0 == strcasecmp(p->key, key))
            return p->val;
        p = p->next;
    }
    return 0;
}

const char *
http_url_fragment(http_url_t *url) {
    return url->fragment;
}

const char *
http_url_userinfo(http_url_t *url) {
    return url->userinfo;
}

int
http_url_build(http_url_t *url, char *s) {
    http_param_t *p;
    char *schema;
    char *path;
    int port;
    int len;

    if (url->schema)
        schema = url->schema;
    else
        schema = "http";
    if (url->port)
        port = url->port;
    else if (0 == strcmp(schema, "https"))
        port = 443;
    else
        port = 90;
    if (url->path)
        path = url->path;
    else
        path = "";

    len = sprintf(s, "%s://%s", schema, url->host);
    if ((port != 80 && strcmp(schema, "http")) || (port != 443 && strcmp(schema, "https"))) {
        char sport[6] = {0};

        sprintf(sport, "%d", port);
        strcat(s, ":");
        strcat(s, sport);
        len += 1 + strlen(sport);
    }
    strcat(s, path);
    len += strlen(path);
    p = url->params.head;
    if (p) {
        strcat(s, "?");
        len += 1;
        while (p) {
            strcat(s, p->key);
            strcat(s, "=");
            strcat(s, p->val);
            len += strlen(p->key) + 1 + strlen(p->val);
            if (p->next) {
                strcat(s, "&");
                len += 1;
            }
            p = p->next;
        }
    }
    if (url->fragment) {
        strcat(s, "#");
        strcat(s, url->fragment);
        len += 1 + strlen(url->fragment);
    }

    return len;
}

int
http_url_parse(http_url_t *url, const char *s) {
    struct http_parser_url u;
    int off, len, rc;

    http_parser_url_init(&u);
    rc = http_parser_parse_url(s, strlen(s), 0, &u);
    if (rc)
        return rc;

    if (u.field_set & (1 << UF_SCHEMA)) {
        off = u.field_data[UF_SCHEMA].off;
        len = u.field_data[UF_SCHEMA].len;
        url->schema = strndup(s + off, len);
    }
    if (u.field_set & (1 << UF_HOST)) {
        off = u.field_data[UF_HOST].off;
        len = u.field_data[UF_HOST].len;
        url->host = strndup(s + off, len);
    }
    if (u.field_set & (1 << UF_PORT)) {
        url->port = u.port;
    } else if (url->schema && 0 == strcasecmp(url->schema, "http")) {
        url->port = 80;
    } else if (url->schema && 0 == strcasecmp(url->schema, "https")) {
        url->port = 443;
    }
    if (u.field_set & (1 << UF_PATH)) {
        off = u.field_data[UF_PATH].off;
        len = u.field_data[UF_PATH].len;
        url->path = strndup(s + off, len);
    }
    if (u.field_set & (1 << UF_QUERY)) {
        off = u.field_data[UF_QUERY].off;
        len = u.field_data[UF_QUERY].len;
        char query[len + 1];
        strncpy(query, s + off, len);
        query[len] = '\0';
        __param_clear(url);
        __param_parse(url, query);
    }
    if (u.field_set & (1 << UF_FRAGMENT)) {
        off = u.field_data[UF_FRAGMENT].off;
        len = u.field_data[UF_FRAGMENT].len;
        url->fragment = strndup(s + off, len);
    }
    if (u.field_set & (1 << UF_USERINFO)) {
        off = u.field_data[UF_USERINFO].off;
        len = u.field_data[UF_USERINFO].len;
        url->userinfo = strndup(s + off, len);
    }
    return 0;
}

void
http_request_init(http_request_t *req) {
    memset(req, 0, sizeof *req);

    http_parser_init(&req->p.parser, HTTP_REQUEST);
    req->p.parser.data = req;
}

void
http_request_unit(http_request_t *req) {
    __url_clear(&req->url);
    __headers_clear(&req->headers);
    if (req->body.s)
        free(req->body.s);
}

void
http_request_set_method(http_request_t *req, const char *method) {
    req->method = method;
}

void
http_request_set_header(http_request_t *req, const char *field, const char *value) {
    __headers_set(&req->headers, field, value);
}

void
http_request_set_body(http_request_t *req, http_str_t body) {
    if (req->body.s)
        free(req->body.s);
    if (body.n) {
        req->body.s = malloc(body.n);
        memcpy(req->body.s, body.s, body.n);
    }
    req->body.n = body.n;
}

const char *
http_request_method(http_request_t *req) {
    return req->method;
}

http_url_t *
http_request_url(http_request_t *req) {
    return &req->url;
}

http_str_t
http_request_body(http_request_t *req) {
    return req->body;
}

const char *
http_request_header(http_request_t *req, const char *field) {
    return __headers_get(&req->headers, field);
}

http_str_t
http_request_build(http_request_t *req) {
    http_str_t buf;
    http_param_t *p;
    http_header_t *header;
    char url[4096] = {0};
    int guess_size = 4200;
    int has_content_length = 0;
    int size;
    char *data;

    strcat(url, req->url.path);
    p = req->url.params.head;
    if (p) {
        strcat(url, "?");
        while (p) {
            char encval[3 * strlen(p->val) + 1];

            url_encode(p->val, strlen(p->val), encval);
            strcat(url, p->key);
            strcat(url, "=");
            strcat(url, encval);
            if (p->next) {
                strcat(url, "&");
            }
            p = p->next;
        }
    }
    if (req->url.fragment) {
        strcat(url, "#");
        strcat(url, req->url.fragment);
    }

    if (req->url.userinfo) {
        char auth[2 * strlen(req->url.userinfo) + 10];
        strcpy(auth, "Basic ");
        base64_encode(req->url.userinfo, strlen(req->url.userinfo), auth + 6);
        __headers_set(&req->headers, "Authorization", auth);
    }

    header = req->headers.head;
    while (header) {
        if (header->value)
            guess_size += 2 + strlen(header->field) + strlen(header->value);
        header = header->next;
    }
    guess_size += 4 + req->body.n;

    data = malloc(guess_size);
    size = snprintf(data, guess_size, "%s %s HTTP/1.1\r\n", req->method, url);

    header = req->headers.head;
    while (header) {
        if (header->value) {
            size += snprintf(data + size, guess_size - size, "%s:%s\r\n", header->field, header->value);
            if (0 == strcasecmp(header->field, "Content-Length")) {
                has_content_length = 1;
            }
        }
        header = header->next;
    }
    if (has_content_length == 0)
        size += snprintf(data + size, guess_size - size, "Content-Length:%zu\r\n", req->body.n);
    strcat(data + size, "\r\n");
    size += 2;
    if (req->body.n && req->body.s) {
        memcpy(data + size, req->body.s, req->body.n);
        size += req->body.n;
    }
    buf.n = size;
    buf.s = data;
    return buf;
}

static int
__on_request_message_begin(http_parser *p) {
    http_request_t *req = (http_request_t *)p->data;
    __headers_clear(&req->headers);
    req->p.complete = 0;
    return 0;
}

static int
__on_request_url(http_parser *p, const char *at, size_t length) {
    http_request_t *req = (http_request_t *)p->data;
    char url[length + 1];
    strncpy(url, at, length);
    url[length] = '\0';
    http_url_parse(&req->url, url);
    return 0;
}

static int
__on_request_header_field(http_parser *p, const char *at, size_t length) {
    http_request_t *req = (http_request_t *)p->data;
    req->p.field_at = at;
    req->p.field_length = length;
    return 0;
}

static int
__on_request_header_value(http_parser *p, const char *at, size_t length) {
    http_request_t *req = (http_request_t *)p->data;
    char field[req->p.field_length + 1];
    char value[length + 1];
    strncpy(field, req->p.field_at, req->p.field_length);
    field[req->p.field_length] = '\0';
    strncpy(value, at, length);
    value[length] = '\0';
    __headers_set(&req->headers, field, value);
    if (0 == strcmp(field, "Authorization") && 0 == strncmp(value, "Basic ", 6)) {
        char userinfo[length];
        base64_decode(value + 6, length - 6, userinfo);
        if (req->url.userinfo)
            free(req->url.userinfo);
        req->url.userinfo = strdup(userinfo);
    }
    return 0;
}

static int
__on_request_body(http_parser *p, const char *at, size_t length) {
    http_request_t *req = (http_request_t *)p->data;
    char *body = malloc(req->body.n + length);
    if (req->body.s) {
        memcpy(body, req->body.s, req->body.n);
        free(req->body.s);
    }
    memcpy(body + req->body.n, at, length);
    req->body.s = body;
    req->body.n += length;
    return 0;
}

static int
__on_request_message_complete(http_parser *p) {
    http_request_t *req = (http_request_t *)p->data;
    req->method = http_method_str(req->p.parser.method);
    req->p.complete = 1;
    return 0;
}

int
http_request_parse(http_request_t *req, http_str_t buf) {
    static http_parser_settings settings = {.on_message_begin = __on_request_message_begin,
                                            .on_url = __on_request_url,
                                            .on_header_field = __on_request_header_field,
                                            .on_header_value = __on_request_header_value,
                                            .on_body = __on_request_body,
                                            .on_message_complete = __on_request_message_complete};

    size_t parsed = http_parser_execute(&req->p.parser, &settings, buf.s, buf.n);
    if (req->p.parser.http_errno) {
        fprintf(stderr, "http_parser_execute: %s %s\n", http_errno_name(req->p.parser.http_errno),
                http_errno_description(req->p.parser.http_errno));
        return -1;
    }
    if (parsed < buf.n) {
        fprintf(stderr, "http_parse_execute size:%zu, parsed:%zu\n", buf.n, parsed);
        return -1;
    }
    return req->p.complete;
}

void
http_response_init(http_response_t *res) {
    memset(res, 0, sizeof *res);

    http_parser_init(&res->p.parser, HTTP_RESPONSE);
    res->p.parser.data = res;
}

void
http_response_unit(http_response_t *res) {
    __headers_clear(&res->headers);
    if (res->body.s)
        free(res->body.s);
}

void
http_response_set_status(http_response_t *res, int status) {
    res->status = status;
}

void
http_response_set_header(http_response_t *res, const char *field, const char *value) {
    __headers_set(&res->headers, field, value);
}

void
http_response_set_body(http_response_t *res, http_str_t body) {
    if (res->body.s)
        free(res->body.s);
    if (body.n) {
        res->body.s = malloc(body.n);
        memcpy(res->body.s, body.s, body.n);
    }
    res->body.n = body.n;
}

int
http_response_status(http_response_t *res) {
    return res->status;
}

const char *
http_response_header(http_response_t *res, const char *field) {
    return __headers_get(&res->headers, field);
}

http_str_t
http_response_body(http_response_t *res) {
    return res->body;
}

http_str_t
http_response_build(http_response_t *res) {
    http_str_t buf;
    http_header_t *header;
    int guess_size = 100;
    int has_content_length = 0;
    int size;
    char *data;

    header = res->headers.head;
    while (header) {
        if (header->value)
            guess_size += 2 + strlen(header->field) + strlen(header->value);
        header = header->next;
    }
    guess_size += 4 + res->body.n;

    data = malloc(guess_size);
    size = snprintf(data, guess_size, "HTTP/1.1 %d %s\r\n", res->status, http_status_str(res->status));

    header = res->headers.head;
    while (header) {
        if (header->value) {
            size += snprintf(data + size, guess_size - size, "%s:%s\r\n", header->field, header->value);
            if (0 == strcasecmp(header->field, "Content-Length")) {
                has_content_length = 1;
            }
        }
        header = header->next;
    }
    if (has_content_length == 0)
        size += snprintf(data + size, guess_size - size, "Content-Length:%zu\r\n", res->body.n);
    strcat(data + size, "\r\n");
    size += 2;
    if (res->body.n && res->body.s) {
        memcpy(data + size, res->body.s, res->body.n);
        size += res->body.n;
    }
    buf.n = size;
    buf.s = data;
    return buf;
}

static int
__on_response_message_begin(http_parser *p) {
    http_response_t *res = (http_response_t *)p->data;
    __headers_clear(&res->headers);
    res->p.complete = 0;
    return 0;
}

static int
__on_response_header_field(http_parser *p, const char *at, size_t length) {
    http_response_t *res = (http_response_t *)p->data;
    res->p.field_at = at;
    res->p.field_length = length;
    return 0;
}

static int
__on_response_header_value(http_parser *p, const char *at, size_t length) {
    http_response_t *res = (http_response_t *)p->data;
    char field[res->p.field_length + 1];
    char value[length + 1];
    strncpy(field, res->p.field_at, res->p.field_length);
    field[res->p.field_length] = '\0';
    strncpy(value, at, length);
    value[length] = '\0';
    __headers_set(&res->headers, field, value);
    return 0;
}

static int
__on_response_body(http_parser *p, const char *at, size_t length) {
    http_response_t *res = (http_response_t *)p->data;
    char *body = malloc(res->body.n + length);
    if (res->body.s) {
        memcpy(body, res->body.s, res->body.n);
        free(res->body.s);
    }
    memcpy(body + res->body.n, at, length);
    res->body.s = body;
    res->body.n += length;
    return 0;
}

static int
__on_response_message_complete(http_parser *p) {
    http_response_t *res = (http_response_t *)p->data;
    res->status = res->p.parser.status_code;
    res->p.complete = 1;
    return 0;
}

int
http_response_parse(http_response_t *res, http_str_t buf) {
    static http_parser_settings settings = {.on_message_begin = __on_response_message_begin,
                                            .on_header_field = __on_response_header_field,
                                            .on_header_value = __on_response_header_value,
                                            .on_body = __on_response_body,
                                            .on_message_complete = __on_response_message_complete};

    size_t parsed = http_parser_execute(&res->p.parser, &settings, buf.s, buf.n);
    if (res->p.parser.http_errno) {
        fprintf(stderr, "http_parser_execute: %s %s\n", http_errno_name(res->p.parser.http_errno),
                http_errno_description(res->p.parser.http_errno));
        return -1;
    }
    if (parsed < buf.n) {
        fprintf(stderr, "http_parse_execute size:%zu, parsed:%zu\n", buf.n, parsed);
        return -1;
    }
    return res->p.complete;
}

#endif /* HTTP_IMPL */
