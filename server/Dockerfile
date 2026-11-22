# ZeroLeakage Server — network DNS filter (UDP/TCP 53, DoT 853, DoH 443) + dashboard/API (3080)
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/zeroleakage-server ./cmd/zeroleakage-server

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata libcap \
 && adduser -D -H -u 10001 zl \
 && mkdir -p /data && chown zl /data
COPY --from=build /out/zeroleakage-server /usr/local/bin/zeroleakage-server
# allow binding 53/443/853 without root
RUN setcap cap_net_bind_service=+ep /usr/local/bin/zeroleakage-server
USER zl
ENV ZL_DATA=/data
VOLUME /data
EXPOSE 53/udp 53/tcp 853/tcp 443/tcp 3080/tcp
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:3080/api/v1/status >/dev/null || exit 1
ENTRYPOINT ["zeroleakage-server"]
