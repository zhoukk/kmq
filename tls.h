/*
 * tls.h
 *
 * Copyright (c) zhoukk <izhoukk@gmail.com>
 *
 * +------+                                    +-----+
 * |......|--> read(fd) --> BIO_write(rbio) -->|.....|--> SSL_read(ssl)  --> IN
 * |......|                                    |.....|
 * |.sock.|                                    |.SSL.|
 * |......|                                    |.....|
 * |......|<-- write(fd) <-- BIO_read(wbio) <--|.....|<-- SSL_write(ssl) <-- OUT
 * +------+                                    +-----+
 *
 *        |                                  |       |                     |
 *        |<-------------------------------->|       |<------------------->|
 *        |         encrypted bytes          |       |  unencrypted bytes  |
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

#ifndef _TLS_H_
#define _TLS_H_

#define TLS_IO_BUFF_SIZE 4096

typedef enum { TLS_MODE_SERVER, TLS_MODE_CLIENT } tls_mode_e;

typedef struct tls_ctx tls_ctx_t;

void tls_init();
void tls_unit();

tls_ctx_t *tls_server_ctx(const char *cert, const char *key);
tls_ctx_t *tls_client_ctx();

void tls_ctx_destroy(tls_ctx_t *ctx);

typedef struct tls tls_t;

typedef int tls_io_write_pt(tls_t *, void *io, void *ud, const void *data, int size);

typedef void tls_on_open_pt(tls_t *, void *io, void *ud);
typedef void tls_on_data_pt(tls_t *, void *io, void *ud, const void *data, int size);
typedef void tls_on_close_pt(tls_t *, void *io, void *ud);

typedef struct {
    tls_on_open_pt *on_open;
    tls_on_data_pt *on_data;
    tls_on_close_pt *on_close;

    tls_io_write_pt *write;
    void *io;

    void *ud;
} tls_config_t;

tls_t *tls_create(tls_ctx_t *ctx, tls_config_t *cfg);
void tls_destroy(tls_t *tls);

int tls_connect(tls_t *tls);
void tls_shutdown(tls_t *tls);
void tls_close(tls_t *tls);
int tls_feed(tls_t *tls, const void *data, int size);
int tls_write(tls_t *tls, const void *data, int size);

#endif // _TLS_H_

#ifdef TLS_IMPL

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

/**
 * Implement
 */

typedef enum {
    TLS_STATE_INIT,
    TLS_STATE_HANDSHAKE,
    TLS_STATE_IO,
    TLS_STATE_CLOSING,
} tls_state_e;

struct tls_ctx {
    SSL_CTX *ssl_ctx;
    tls_mode_e mode;
};

struct tls {
    SSL *ssl;
    BIO *read_bio;
    BIO *write_bio;
    tls_config_t cfg;
    int state;
};

void
tls_init() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
}

void
tls_unit() {
    EVP_cleanup();
    ERR_free_strings();
}

tls_ctx_t *
tls_server_ctx(const char *cert, const char *key) {
    tls_ctx_t *ctx;
    SSL_CTX *ssl_ctx;

    ctx = 0;
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, 0);

    if (SSL_CTX_load_verify_locations(ssl_ctx, cert, key) != 1)
        ERR_print_errors_fp(stderr);
    if (SSL_CTX_set_default_verify_paths(ssl_ctx) != 1)
        ERR_print_errors_fp(stderr);
    if (SSL_CTX_use_certificate_file(ssl_ctx, cert, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        goto e;
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        goto e;
    }
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        ERR_print_errors_fp(stderr);
        goto e;
    }

    ctx = (tls_ctx_t *)malloc(sizeof *ctx);
    memset(ctx, 0, sizeof *ctx);

    ctx->ssl_ctx = ssl_ctx;
    ctx->mode = TLS_MODE_SERVER;

e:
    return ctx;
}

tls_ctx_t *
tls_client_ctx() {
    tls_ctx_t *ctx;

    ctx = (tls_ctx_t *)malloc(sizeof *ctx);
    memset(ctx, 0, sizeof *ctx);

    ctx->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    ctx->mode = TLS_MODE_CLIENT;

    return ctx;
}

void
tls_ctx_destroy(tls_ctx_t *ctx) {
    SSL_CTX_free(ctx->ssl_ctx);
}

tls_t *
tls_create(tls_ctx_t *ctx, tls_config_t *cfg) {
    tls_t *tls;

    tls = (tls_t *)malloc(sizeof *tls);
    memset(tls, 0, sizeof *tls);

    tls->ssl = SSL_new(ctx->ssl_ctx);
    if (ctx->mode == TLS_MODE_SERVER) {
        SSL_set_accept_state(tls->ssl);
    } else {
        SSL_set_connect_state(tls->ssl);
    }
    tls->read_bio = BIO_new(BIO_s_mem());
    tls->write_bio = BIO_new(BIO_s_mem());
    BIO_set_nbio(tls->read_bio, 1);
    BIO_set_nbio(tls->write_bio, 1);
    SSL_set_bio(tls->ssl, tls->read_bio, tls->write_bio);
    SSL_set_mode(tls->ssl, SSL_MODE_AUTO_RETRY);

    tls->state = TLS_STATE_INIT;

    tls->cfg = *cfg;
    return tls;
}

void
tls_shutdown(tls_t *tls) {
    SSL_shutdown(tls->ssl);
    tls->state = TLS_STATE_CLOSING;
}

void
tls_close(tls_t *tls) {
    if (tls->cfg.on_close) {
        tls->cfg.on_close(tls, tls->cfg.io, tls->cfg.ud);
    }
}

void
tls_destroy(tls_t *tls) {
    SSL_free(tls->ssl);
    free(tls);
}

int
tls_connect(tls_t *tls) {
    int ret;

    ret = SSL_do_handshake(tls->ssl);
    if (ret == 1) {
        return -1;
    }

    if (SSL_is_init_finished(tls->ssl)) {
        return -1;
    }
    ret = SSL_connect(tls->ssl);
    if (ret < 0 && SSL_get_error(tls->ssl, ret) == SSL_ERROR_WANT_READ) {
        return 0;
    }

    return -1;
}

int
tls_feed(tls_t *tls, const void *data, int size) {
    char buf[TLS_IO_BUFF_SIZE];
    int ret;

    BIO_write(tls->read_bio, data, size);

    if (tls->state == TLS_STATE_INIT || tls->state == TLS_STATE_HANDSHAKE) {
        tls->state = TLS_STATE_HANDSHAKE;
        ret = SSL_do_handshake(tls->ssl);
        switch (ret) {
        case 1:
            tls->state = TLS_STATE_IO;
            if (tls->cfg.on_open) {
                tls->cfg.on_open(tls, tls->cfg.io, tls->cfg.ud);
            }
            break;
        case 0:
            tls->state = TLS_STATE_CLOSING;
            break;
        case -1:
            ret = SSL_get_error(tls->ssl, ret);
            switch (ret) {
            case SSL_ERROR_WANT_READ:
                break;
            default:
                tls->state = TLS_STATE_CLOSING;
                break;
            }
            break;
        default:
            tls->state = TLS_STATE_CLOSING;
            break;
        }
        if (tls->state == TLS_STATE_HANDSHAKE || tls->state == TLS_STATE_IO) {
            while ((ret = BIO_read(tls->write_bio, buf, TLS_IO_BUFF_SIZE)) > 0) {
                tls->cfg.write(tls, tls->cfg.io, tls->cfg.ud, buf, ret);
            }
            BIO_flush(tls->write_bio);
        }
        if (tls->state == TLS_STATE_CLOSING) {
            return -1;
        }
    }

    while ((ret = SSL_read(tls->ssl, buf, TLS_IO_BUFF_SIZE)) > 0) {
        if (tls->cfg.on_data) {
            tls->cfg.on_data(tls, tls->cfg.io, tls->cfg.ud, buf, ret);
        }
    }
    if (ret <= 0) {
        if (ret == 0 || SSL_get_error(tls->ssl, ret) != SSL_ERROR_WANT_READ) {
            if (tls->cfg.on_close) {
                tls->cfg.on_close(tls, tls->cfg.io, tls->cfg.ud);
            }
            return -1;
        }
    }
    return 0;
}

int
tls_write(tls_t *tls, const void *data, int size) {
    int ret;
    char buf[TLS_IO_BUFF_SIZE];

    ret = SSL_write(tls->ssl, data, size);
    if (ret <= 0) {
        return -1;
    }

    while ((ret = BIO_read(tls->write_bio, buf, TLS_IO_BUFF_SIZE)) > 0) {
        tls->cfg.write(tls, tls->cfg.io, tls->cfg.ud, buf, ret);
    }
    BIO_flush(tls->write_bio);
    return 0;
}

#endif /* TLS_IMPL */
