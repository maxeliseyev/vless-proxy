# Release image of the h3 server: wraps the prebuilt static musl binaries
# from the release workflow (dist/<arch>/vproxy-server).
FROM alpine:3.21
ARG TARGETARCH
RUN apk add --no-cache ca-certificates && mkdir -p /etc/vproxy-server
COPY dist/${TARGETARCH}/vproxy-server /usr/local/bin/vproxy-server
EXPOSE 443/udp
ENTRYPOINT ["vproxy-server"]
CMD ["-c", "/etc/vproxy-server/server.toml"]
