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

FROM alpine:3.21

# openssl -> X25519 key generation for the test keypairs (hex, as UAPI expects)
RUN apk add --no-cache bash curl python3 iproute2 openssl

COPY --from=awg-build /out/amneziawg-go /usr/local/bin/amneziawg-go
COPY entrypoint.sh /opt/entrypoint.sh
COPY awg-server.sh /opt/awg-server.sh
COPY uapi_set.py /opt/uapi_set.py
COPY origin.py /opt/origin.py
RUN chmod +x /opt/entrypoint.sh /opt/awg-server.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
