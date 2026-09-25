# Proxmox Backup Server, containerised.
#
# Upstream ships PBS for bare metal / VM only — there is no official image, so we
# build one from the same Debian base and `pbs-no-subscription` repo the ISO uses.
# That keeps the provenance first-party (Proxmox's own packages) with no
# third-party image in the supply chain.
#
# Alpine was evaluated 2026-09-25 and is NOT possible here: `ldd
# proxmox-backup-proxy` resolves 27 libraries, among them libc.so.6 +
# /lib64/ld-linux-x86-64.so.2 (glibc, so musl is out) and libapt-pkg.so.7.0 --
# Debian's own APT library, which PBS links for its package/update views.
# `gcompat` can shim glibc but nothing supplies libapt-pkg, and Proxmox ships
# PBS as .deb only, so Fedora/RPM bases fail for the same two reasons.
# Don't "modernise" this to alpine; re-check with ldd first if you're tempted.
FROM debian:trixie-slim

ARG PBS_COMPONENT=pbs-no-subscription
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg tini procps util-linux passwd \
 && curl -fsSL https://enterprise.proxmox.com/debian/proxmox-release-trixie.gpg \
      -o /etc/apt/trusted.gpg.d/proxmox-release-trixie.gpg \
 && chmod 0644 /etc/apt/trusted.gpg.d/proxmox-release-trixie.gpg \
 && echo "deb http://download.proxmox.com/debian/pbs trixie ${PBS_COMPONENT}" \
      > /etc/apt/sources.list.d/pbs.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends proxmox-backup-server \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

# Config (incl. authkey.key / proxy.pem — server identity) and logs persist.
VOLUME ["/etc/proxmox-backup", "/var/log/proxmox-backup"]
EXPOSE 8007

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD curl -fsk https://127.0.0.1:8007/api2/json/ping >/dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
