FROM alpine:3.21

# The mock exit node. Runs a plain HTTP origin now; the server-side transport
# cores are added at T018 once Phase 3 needs a real handshake.
RUN apk add --no-cache bash curl python3 iproute2

COPY entrypoint.sh /opt/entrypoint.sh
COPY origin.py /opt/origin.py
RUN chmod +x /opt/entrypoint.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
