/*
 * ini.h -- ini library.
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

#ifndef _INI_H_
#define _INI_H_

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INI_LINE_MAX_LEN 1024

typedef int ini_kv_pt(void *ud, const char *section, const char *key, const char *value);

int ini_parse(const char *file, ini_kv_pt *on_kv, void *ud);

#endif /* _INI_H_ */

#ifdef INI_IMPL

static char *
trim_left(char *p) {
    while (*p && isspace(*p)) {
        p++;
    }
    return p;
}

static char *
trim_right(char *p) {
    size_t n;

    n = strlen(p);
    while ((n > 0) && ((p[n - 1] == '\n') || isspace(p[n - 1]))) {
        p[n - 1] = '\0';
        n--;
    }
    return p;
}

int
ini_parse(const char *file, ini_kv_pt *on_kv, void *ud) {
    FILE *f;
    char line[INI_LINE_MAX_LEN];
    char section[INI_LINE_MAX_LEN];
    int rc;

    f = fopen(file, "r");
    if (!f) {
        return -1;
    }
    section[0] = '\0';
    rc = 0;
    while (!feof(f) && fgets(line, INI_LINE_MAX_LEN, f) && !rc) {
        char *p, *s, *k, *v;

        p = trim_left(line);
        p = trim_right(p);
        if (*p == '\0' || *p == '#' || *p == ';') {
            continue;
        }
        if (*p == '[') {
            s = strtok(p, "]");
            if (s) {
                s = trim_left(s + 1);
                s = trim_right(s);
                strcpy(section, s);
            }
            continue;
        }
        k = strtok(p, "=");
        if (!k) {
            continue;
        }
        v = strtok(0, "=");
        k = trim_left(k);
        k = trim_right(k);
        if (v) {
            v = trim_left(v);
            v = trim_right(v);
        }
        s = section;
        rc = on_kv(ud, s, k, v);
    }
    fclose(f);
    return rc;
}

#endif /* INI_IMPL */
