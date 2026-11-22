# Image for the Compose dev setup (../compose.yaml). The mesh hosts and the
# tenant containers both run it: the hosts for the daemon, the tenants for the
# network tools.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
RUN CGO_ENABLED=0 go build -trimpath -o /open6pn ./cmd/open6pn

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      iproute2 iputils-ping dnsutils wireguard-tools iperf3 socat curl jq procps \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /open6pn /usr/local/bin/open6pn
COPY dev/host.sh /usr/local/bin/open6pn-dev-host
