FROM alpine:3.21

# iproute2 -> tc/netem/tbf ; iptables -> DPI and block simulation
# socat     -> port forwarding to the endpoint
# tcpdump   -> packet inspection
# python3   -> report.sh, the DNS forger, the captive portal, and test probes
RUN apk add --no-cache         iproute2 iproute2-tc iptables ip6tables         socat tcpdump bash curl jq procps python3

COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
