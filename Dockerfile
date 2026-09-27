# ---- build ----
FROM rust:1-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# ---- runtime ----
FROM alpine:3
RUN apk add --no-cache ca-certificates tzdata
ENV TZ=Asia/Shanghai
COPY --from=builder /src/target/release/ysptp-project /usr/local/bin/ysptp-project
VOLUME ["/data"]
EXPOSE 8766
ENTRYPOINT ["/usr/local/bin/ysptp-project", \
    "--meta-json", "/data/proxy-cache-state-rs.json", \
    "--device-json", "/data/device-state-rs.json"]
CMD ["--port", "8766"]
