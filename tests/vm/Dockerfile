# Real-reboot verification of SUIT for Linux. Boots a Debian 12 cloud image
# in QEMU, so the guest has its own kernel and a reboot is a genuine kernel
# reboot (new boot_id, CLOCK_BOOTTIME reset). Build from the repository root:
#   docker build -f tests/vm/Dockerfile -t suit-vm . && docker run --rm -v suit-vm-cache:/cache suit-vm
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      qemu-system-x86 qemu-utils cloud-image-utils openssh-client curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY suitlinux /src/suitlinux
COPY bin /src/bin
COPY etc /src/etc
COPY tests/e2e /src/tests/e2e
COPY tests/vm /src/tests/vm
CMD ["sh", "/src/tests/vm/run.sh"]
