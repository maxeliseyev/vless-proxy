# Release image: wraps the prebuilt static musl binaries from the release
# workflow (dist/<arch>/vproxy), one image for linux/amd64 and linux/arm64.
FROM alpine:3.21
ARG TARGETARCH
RUN apk add --no-cache ca-certificates && mkdir -p /data /root/.config/vproxy
COPY dist/${TARGETARCH}/vproxy /usr/local/bin/vproxy
VOLUME ["/data"]
EXPOSE 1080
ENTRYPOINT ["vproxy", "-l", "0.0.0.0", "-p", "1080"]
CMD ["-f", "/data/server.txt"]
