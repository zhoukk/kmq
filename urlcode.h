#ifndef _URLCODE_H_
#define _URLCODE_H_

int url_encode(const char *in, int len, char *out);

int url_decode(const char *in, int len, char *out);

#endif /* _URLCODE_H_ */

#ifdef URLCODE_IMPL

#include <ctype.h>

int
__hex2dec(char c) {
    if ('0' <= c && c <= '9') {
        return c - '0';
    } else if ('a' <= c && c <= 'f') {
        return c - 'a' + 10;
    } else if ('A' <= c && c <= 'F') {
        return c - 'A' + 10;
    } else {
        return -1;
    }
}

int
url_encode(const char *in, int len, char *out) {
    int i, j;
    static const char __hexchars[] = "0123456789ABCDEF";

    for (i = 0, j = 0; i < len; ++i) {
        char c = in[i];
        if (c == ' ') {
            out[j++] = '+';
        } else if (('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || c == '/' || c == '.') {
            out[j++] = c;
        } else {
            out[j++] = '%';
            out[j++] = __hexchars[(unsigned char)c >> 4];
            out[j++] = __hexchars[(unsigned char)c & 15];
        }
    }
    out[j] = '\0';
    return j;
}

int
url_decode(const char *in, int len, char *out) {
    int i, j;

    for (i = 0, j = 0; i < len; ++i) {
        char c = in[i];
        if (c == '+') {
            out[j++] = ' ';
        } else if (c == '%' && len - i >= 2 && isxdigit(in[i + 1]) && isxdigit(in[i + 2])) {
            char h = in[++i];
            char l = in[++i];
            out[j++] = (char)(__hex2dec(h) * 16 + __hex2dec(l));
        } else {
            out[j++] = c;
        }
    }
    out[j] = '\0';
    return j;
}

#endif /* URLCODE_IMPL */