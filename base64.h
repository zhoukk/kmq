#ifndef _BASE64_H_
#define _BASE64_H_

int base64_encode(const char *in, int len, char *out);

int base64_decode(const char *in, int len, char *out);

#endif /* _BASE64_H_ */

#ifdef BASE64_IMPL

static const char __base64_e[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/',
};

static const char __base64_d[] = {
    /* '+', ',', '-', '.', '/', '0', '1', '2', */
    62,  -1,  -1,  -1,  63,  52,  53,  54,

    /* '3', '4', '5', '6', '7', '8', '9', ':', */
    55,  56,  57,  58,  59,  60,  61,  -1,

    /* ';', '<', '=', '>', '?', '@', 'A', 'B', */
	-1,  -1,  -1,  -1,  -1,  -1,   0,   1, 

	/* 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', */
    2,   3,   4,   5,   6,   7,   8,   9,

	/* 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', */
    10,  11,  12,  13,  14,  15,  16,  17,

	/* 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', */
    18,  19,  20,  21,  22,  23,  24,  25,

	/* '[', '\', ']', '^', '_', '`', 'a', 'b', */
    -1,  -1,  -1,  -1,  -1,  -1,  26,  27,

	/* 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', */
    28,  29,  30,  31,  32,  33,  34,  35,

	/* 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', */
    36,  37,  38,  39,  40,  41,  42,  43,

	/* 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', */
    44,  45,  46,  47,  48,  49,  50,  51,
};

int
base64_encode(const char *in, int len, char *out) {
    int i, j;
    unsigned char *uin;

    uin = (unsigned char *)in;
    for (i = j = 0; i < len; i++) {
        int s = i % 3;

        switch (s) {
        case 0:
            out[j++] = __base64_e[(uin[i] >> 2) & 0x3F];
            continue;
        case 1:
            out[j++] = __base64_e[((uin[i - 1] & 0x3) << 4) + ((uin[i] >> 4) & 0xF)];
            continue;
        case 2:
            out[j++] = __base64_e[((uin[i - 1] & 0xF) << 2) + ((uin[i] >> 6) & 0x3)];
            out[j++] = __base64_e[uin[i] & 0x3F];
        }
    }
    i -= 1;

    if ((i % 3) == 0) {
        out[j++] = __base64_e[(uin[i] & 0x3) << 4];
        out[j++] = '=';
        out[j++] = '=';
    } else if ((i % 3) == 1) {
        out[j++] = __base64_e[(uin[i] & 0xF) << 2];
        out[j++] = '=';
    }
    out[j] = '\0';

    return j;
}

int
base64_decode(const char *in, int len, char *out) {
    int i, j;
    unsigned char *uout;

    uout = (unsigned char *)out;
    for (i = j = 0; i < len; i++) {
        int c;
        int s = i % 4;

        if (in[i] == '=')
            break;

        if (in[i] < '+' || in[i] > 'z' || (c = __base64_d[in[i] - '+']) == -1)
            break;

        switch (s) {
        case 0:
            uout[j] = ((unsigned int)c << 2) & 0xFF;
            continue;
        case 1:
            uout[j++] += ((unsigned int)c >> 4) & 0x3;
            if (i < (len - 3) || in[len - 2] != '=')
                uout[j] = ((unsigned int)c & 0xF) << 4;
            continue;
        case 2:
            uout[j++] += ((unsigned int)c >> 2) & 0xF;
            if (i < (len - 2) || in[len - 1] != '=')
                uout[j] = ((unsigned int)c & 0x3) << 6;
            continue;
        case 3:
            uout[j++] += (unsigned char)c;
        }
    }
    uout[j] = '\0';

    return j;
}

#endif /* BASE64_IMPL */