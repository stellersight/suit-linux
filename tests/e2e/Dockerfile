# End-to-end verification of SUIT for Linux with real sudo, users and the
# kernel's boot clock. Build from the repository root:
#   docker build -f tests/e2e/Dockerfile -t suit-e2e . && docker run --rm suit-e2e
ARG BASE=debian:12-slim
FROM ${BASE}
RUN if command -v apt-get >/dev/null; then \
      apt-get update && apt-get install -y --no-install-recommends sudo python3 passwd && rm -rf /var/lib/apt/lists/*; \
    elif command -v dnf >/dev/null; then dnf install -y sudo python3 shadow-utils util-linux findutils && dnf clean all; \
    elif command -v microdnf >/dev/null; then microdnf install -y sudo python3 shadow-utils util-linux findutils && microdnf clean all; \
    elif command -v apk >/dev/null; then apk add --no-cache sudo python3 shadow coreutils; fi
COPY suitlinux /usr/lib/suit/suitlinux
COPY bin/suit bin/suit-exec /usr/sbin/
COPY etc/sudoers.suit /etc/sudoers.d/suit
COPY tests/e2e/profiles.json tests/e2e/eligibility.json /etc/suit/
COPY tests/e2e/run.sh /root/run.sh
RUN set -e; \
    find /usr/lib/suit -name __pycache__ -prune -exec rm -rf {} +; \
    # Executable paths differ by distribution (Alpine: /bin/touch -> coreutils). \
    sed -i "s#/usr/bin/touch#$(command -v touch)#; s#/usr/bin/id#$(command -v id)#; s#/usr/bin/head#$(command -v head)#" /etc/suit/profiles.json; \
    chown -R root:root /usr/lib/suit /etc/suit /usr/sbin/suit /usr/sbin/suit-exec; \
    chmod -R go-w /usr/lib/suit /etc/suit; chmod 0755 /usr/sbin/suit /usr/sbin/suit-exec; \
    chmod 0440 /etc/sudoers.d/suit; visudo -cf /etc/sudoers.d/suit; \
    install -d -m 0700 /var/lib/suit; \
    groupadd -f suit-eligible; groupadd -f suit-approvers; \
    useradd -m -u 1001 -G suit-eligible alice; useradd -m -u 2000 -G suit-approvers bob; \
    echo 'bob:approver-pass' | chpasswd; chmod 0700 /root/run.sh
CMD ["/root/run.sh"]
