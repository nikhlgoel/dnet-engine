# T200 - a server for the lab: an Ubuntu with systemd, so the product's own setup script (which installs systemd
# units, iptables rules and two services) can run on it exactly as it would on a cloud machine. See README.md.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive container=docker
# Retries and a long timeout: on a slow connection a mirror can stall, and one stalled download should not end the build.
RUN printf 'Acquire::Retries "8";\nAcquire::http::Timeout "90";\nAcquire::https::Timeout "90";\n' > /etc/apt/apt.conf.d/80lab \
 && apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv iproute2 iptables curl python3 openssl \
      ca-certificates procps \
 && apt-get clean \
 && find /var/lib/apt/lists -type f -delete
# A container has no console, login manager, or hardware to wait for.
RUN systemctl mask getty.target console-getty.service systemd-logind.service systemd-udevd.service \
      systemd-udev-trigger.service systemd-resolved.service apt-daily.timer apt-daily-upgrade.timer \
      motd-news.timer e2scrub_all.timer fstrim.timer
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
