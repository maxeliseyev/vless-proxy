# Build vproxy from source on Alpine (static musl binary) and ship it in a
# minimal image. Multi-arch friendly: `docker buildx build --platform
# linux/amd64,linux/arm64 .` Published images: ghcr.io/maxeliseyev/vproxy
#
#   docker run -d --name vproxy -p 1080:1080 \
#     -v "$PWD/server.txt:/data/server.txt:ro" ghcr.io/maxeliseyev/vproxy
#   docker run -d --name vproxy -p 1080:1080 ghcr.io/maxeliseyev/vproxy \
#     -l 0.0.0.0 -s 'https://provider/sub/token'

FROM rust:1-alpine AS build
RUN apk add --no-cache build-base cmake perl git linux-headers
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build -p vproxy --release --locked && strip target/release/vproxy

FROM alpine:3.21
RUN apk add --no-cache ca-certificates && mkdir -p /data /root/.config/vproxy
COPY --from=build /src/target/release/vproxy /usr/local/bin/vproxy
VOLUME ["/data"]
EXPOSE 1080
ENTRYPOINT ["vproxy", "-l", "0.0.0.0", "-p", "1080"]
# server.txt mounted into /data, or pass -s URL / -u 'vless://...' instead
CMD ["-f", "/data/server.txt"]
