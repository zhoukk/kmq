FROM alpine AS builder

WORKDIR /app

ADD . .

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk add --no-cache build-base cmake libuv-dev openssl-dev \
    && cmake -B build && cmake --build build -j

FROM alpine

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk add --no-cache libuv openssl

COPY --from=builder /app/build/mqtt_broker .
COPY --from=builder /app/build/mqtt_sn_gateway .
COPY --from=builder /app/build/mqtt_pub .
COPY --from=builder /app/build/mqtt_sub .
COPY --from=builder /app/build/mqtt_sn_pub .
COPY --from=builder /app/build/mqtt_sn_sub .
COPY --from=builder /app/build/mqtt_sn_cli_test .
COPY --from=builder /app/build/mqtt_cli_test .
COPY --from=builder /app/build/mqtt_test .
COPY --from=builder /app/broker.ini .

EXPOSE 1883
EXPOSE 1884

CMD ["/broker.ini"]
ENTRYPOINT ["/mqtt_broker"]
