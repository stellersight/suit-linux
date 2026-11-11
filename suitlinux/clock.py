"""Boot-scoped time.

Grants are measured against CLOCK_BOOTTIME, which counts time since boot
(including suspend) and cannot be set by an administrator, and are bound to
the kernel's per-boot identifier. A grant therefore cannot be extended by
changing the wall clock, and does not survive a reboot.
"""

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


def boot_seconds() -> float:
    """Returns seconds since boot from CLOCK_BOOTTIME."""
    if not hasattr(time, "CLOCK_BOOTTIME"):
        raise ClockUnavailable("CLOCK_BOOTTIME is not available on this platform")
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def wall_iso() -> str:
    """Returns the wall-clock time for human-readable records only."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
