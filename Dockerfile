FROM alpine AS builder

WORKDIR /app

ADD . .

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk add gcc g++ make autoconf automake libtool libuv-dev openssl-dev \
    && ./autogen.sh && ./configure && make

FROM alpine

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk add libuv openssl

COPY --from=builder /app/mqtt_broker .
COPY --from=builder /app/mqtt_proxy .
COPY --from=builder /app/mqtt_sn_gateway .
COPY --from=builder /app/mqtt_pub .
COPY --from=builder /app/mqtt_sub .
COPY --from=builder /app/mqtt_sn_pub .
COPY --from=builder /app/mqtt_sn_sub .
COPY --from=builder /app/mqtt_sn_cli_test .
COPY --from=builder /app/mqtt_cli_test .
COPY --from=builder /app/mqtt_test .

EXPOSE 1883
EXPOSE 8883
EXPOSE 8083
EXPOSE 8084