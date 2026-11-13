# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
"""Boot-scoped time.

Grants are measured against CLOCK_BOOTTIME, which counts time since boot
(including suspend) and cannot be set by an administrator, and are bound to
the kernel's per-boot identifier. A grant therefore cannot be extended by
changing the wall clock, and does not survive a reboot.
"""

import os
import time
from pathlib import Path

BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")


class ClockUnavailable(RuntimeError):
    """Raised where a trustworthy boot identity or boot clock cannot be read."""


def boot_id() -> str:
    """Returns the kernel's boot identifier.

    There is deliberately no fallback. A constant substitute would let grants
    survive reboot, so the caller must fail closed instead.
    """
    try:
        value = BOOT_ID_PATH.read_text(encoding="ascii").strip()
    except OSError as e:
        raise ClockUnavailable(f"cannot read {BOOT_ID_PATH}: {e}") from e
    if not value:
        raise ClockUnavailable(f"{BOOT_ID_PATH} is empty")
    return value


def check_host_time_namespace(readlink=os.readlink) -> None:
    """Refuses to read the boot clock from inside a separate time namespace.

    Linux 5.6+ time namespaces give CLOCK_BOOTTIME a per-namespace offset, and
    boot_id does not change with them. A process in a namespace whose boot
    clock lags the host's could otherwise see a grant as unexpired. The broker
    therefore requires its time namespace to be that of PID 1. A kernel
    without time namespaces has no /proc/self/ns/time and nothing to check.
    """
    try:
        own = readlink("/proc/self/ns/time")
    except FileNotFoundError:
        return
    except OSError as e:
        raise ClockUnavailable(f"cannot read this process's time namespace: {e}") from e
    try:
        host = readlink("/proc/1/ns/time")
    except OSError as e:
        raise ClockUnavailable(f"cannot read PID 1's time namespace: {e}") from e
    if own != host:
        raise ClockUnavailable("running in a different time namespace from PID 1; the boot clock cannot be trusted")


def boot_seconds() -> float:
    """Returns seconds since boot from CLOCK_BOOTTIME, in the host's time namespace."""
    if not hasattr(time, "CLOCK_BOOTTIME"):
        raise ClockUnavailable("CLOCK_BOOTTIME is not available on this platform")
    check_host_time_namespace()
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def wall_iso() -> str:
    """Returns the wall-clock time for human-readable records only."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
