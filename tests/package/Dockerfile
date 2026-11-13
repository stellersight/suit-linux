# Installs every built .deb or .rpm in dist/ (SUIT for Linux, and Priv-Audit if present), then runs the end-to-end suite against the
# packaged installation. From a directory holding dist/ and this repository:
#   docker build --build-arg BASE=debian:12-slim -f tests/package/Dockerfile -t suit-pkg .
ARG BASE=debian:12-slim
FROM ${BASE}
COPY dist/ /tmp/dist/
RUN set -e; \
    if command -v apt-get >/dev/null; then \
      apt-get update && apt-get install -y --no-install-recommends /tmp/dist/*.deb passwd && rm -rf /var/lib/apt/lists/*; \
    else \
      dnf install -y /tmp/dist/*.rpm shadow-utils util-linux findutils && dnf clean all; \
    fi
COPY tests/e2e/profiles.json tests/e2e/eligibility.json /etc/suit/
COPY tests/e2e/run.sh /root/run.sh
RUN set -e; \
    sed -i "s#/usr/bin/touch#$(command -v touch)#; s#/usr/bin/id#$(command -v id)#; s#/usr/bin/head#$(command -v head)#" /etc/suit/profiles.json; \
    chown root:root /etc/suit/*.json; chmod 0644 /etc/suit/*.json; \
    useradd -m -u 1001 -G suit-eligible alice; useradd -m -u 2000 -G suit-approvers bob; \
    echo 'bob:approver-pass' | chpasswd; chmod 0700 /root/run.sh
CMD ["/root/run.sh"]
