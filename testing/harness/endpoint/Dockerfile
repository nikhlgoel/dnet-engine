# The mock exit node.
#
# Serves the plain HTTP origin, and (T018, partial) the Profile A AmneziaWG server that
# SPIKE-R4 needs. The server core is built from source at the SAME pinned commit as the
# client binary (crates/xtask/src/fetch_vendor.rs, ADR-0004), so both ends speak the
# identical obfuscated protocol. `xtask`'s tests assert the two pins agree.

FROM golang:1.25-alpine AS awg-build
ARG AMNEZIAWG_GO_COMMIT=b5928efb6ca19f0153958460c3d141f04abc5c2e
RUN apk add --no-cache git
WORKDIR /src
RUN git init -q \
 && git fetch --quiet --depth 1 https://github.com/amnezia-vpn/amneziawg-go "${AMNEZIAWG_GO_COMMIT}" \
 && git checkout -q FETCH_HEAD \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/amneziawg-go .

# The Profile B (Hysteria 2) and Profile C (VLESS+REALITY) servers are the primary core itself,
# built from the SAME pinned commit as the client binary (crates/xtask/src/fetch_vendor.rs), so
# both ends speak the identical protocol revision. `xtask`'s tests assert the two commits agree.
# Only the server side is needed here, so the TUN-related tags the client uses are omitted;
# `with_quic` serves Hysteria 2 and `with_utls` serves REALITY.
FROM golang:1.25-alpine AS primary-build
ARG PRIMARY_CORE_COMMIT=0b8995879f29a9b98ee027bc17b75e101445b238
RUN apk add --no-cache git
WORKDIR /src
RUN git init -q \
 && git fetch --quiet --depth 1 https://github.com/SagerNet/sing-box "${PRIMARY_CORE_COMMIT}" \
 && git checkout -q FETCH_HEAD \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -tags "with_quic,with_utls" \
      -o /out/primary-core ./cmd/sing-box

FROM alpine:3.21

# openssl -> X25519 test keypairs (hex, as UAPI expects) and the Hysteria 2 server certificate
RUN apk add --no-cache bash curl python3 iproute2 openssl

COPY --from=awg-build /out/amneziawg-go /usr/local/bin/amneziawg-go
COPY --from=primary-build /out/primary-core /usr/local/bin/primary-core
COPY entrypoint.sh /opt/entrypoint.sh
COPY awg-server.sh /opt/awg-server.sh
COPY hy2-server.sh /opt/hy2-server.sh
COPY reality-server.sh /opt/reality-server.sh
COPY reality-target.py /opt/reality-target.py
COPY uapi_set.py /opt/uapi_set.py
COPY origin.py /opt/origin.py
RUN chmod +x /opt/entrypoint.sh /opt/awg-server.sh /opt/hy2-server.sh /opt/reality-server.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
