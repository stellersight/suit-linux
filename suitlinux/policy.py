"""Root-owned policy: which actions exist, and who may request them.

Two files, both under /etc/suit:

profiles.json (suit.profiles.v1)
    Maps a symbolic action name to one exact argument vector. Users choose an
    action by name; they never supply a command, an option or an operand.

eligibility.json (suit.eligibility.v1)
    Lists, per user, the actions they may request and an upper bound on the
    grant duration.

Both are read through a file descriptor opened without following symlinks,
and rejected unless owned by root and not writable by group or others. The
same applies to the directory holding them, so an unprivileged user cannot
swap a file out from under the reader.
"""

import json
import os
import posixpath
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

POLICY_DIR = Path("/etc/suit")

ACTION_NAME_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789.-_")

# CAG-INV-3: no grant on any SUIT platform may exceed four hours. Policy can
# only set a lower limit.
MAX_GRANT_SECONDS = 4 * 3600

# Executables that interpret arbitrary input, open pagers or editors, or run
# sub-commands. An action whose argv[0] is one of these can be steered into a
# root shell however its arguments are fixed, so the loader refuses it.
FORBIDDEN_EXECUTABLES = {
    "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "busybox",
    "python", "python2", "python3", "perl", "ruby", "php", "node", "lua", "tclsh", "awk", "gawk", "mawk",
    "vi", "vim", "nvim", "nano", "emacs", "ed", "less", "more", "most", "man",
    "find", "xargs", "env", "sudo", "su", "doas", "pkexec", "nice", "nohup", "timeout", "watch",
    "tar", "zip", "rsync", "scp", "ssh", "git", "make", "gdb", "strace",
    "tcpdump", "tee", "dd", "cp", "mv", "chmod", "chown", "apt", "apt-get", "dnf", "yum", "apk", "pip",
}


class PolicyError(RuntimeError):
    """Raised when a policy file is unsafe or malformed. The caller must refuse."""


@dataclass(frozen=True)
class Action:
    name: str
    argv: Tuple[str, ...]
    description: str


@dataclass(frozen=True)
class Eligibility:
    uid: int
    actions: frozenset
    max_duration_seconds: int


def _check_owner_and_mode(st: os.stat_result, what: str) -> None:
    if st.st_uid != 0:
        raise PolicyError(f"{what} must be owned by root (uid {st.st_uid})")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PolicyError(f"{what} must not be writable by group or others (mode {oct(stat.S_IMODE(st.st_mode))})")


def check_trusted_path(path: str, lstat=os.lstat) -> None:
    """Requires every component of an absolute path to be root-controlled.

    O_NOFOLLOW only covers the final component. A symlink, or a directory an
    unprivileged user can write, anywhere above it would let that user
    substitute what is read or executed. So each component from / down is
    checked: no symlinks, owned by root, not writable by group or others.
    """
    if not path.startswith("/"):
        raise PolicyError(f"{path} is not absolute")
    current = "/"
    parts = [p for p in path.split("/") if p]
    for i, part in enumerate([""] + parts):
        if part:
            current = posixpath.join(current, part)
        try:
            st = lstat(current)
        except OSError as e:
            raise PolicyError(f"cannot inspect {current}: {e}") from e
        if stat.S_ISLNK(st.st_mode):
            raise PolicyError(f"{current} is a symlink; trusted paths must not contain symlinks")
        _check_owner_and_mode(st, current)


def check_executable(path: str, lstat=os.lstat, read_head=None) -> None:
    """Requires a profile's executable to be a root-controlled regular file.

    A fixed argument list does not make a program safe to run as root if an
    unprivileged user can replace the program, a directory above it, or (for
    a script) its interpreter.
    """
    st = lstat(path)
    if stat.S_ISLNK(st.st_mode):
        # Distributions routinely symlink executables (python3 -> python3.12).
        # Acceptable only if the link itself is root's, in a trusted
        # directory, and its target passes the same checks.
        check_trusted_path(posixpath.dirname(path), lstat)
        if st.st_uid != 0:
            raise PolicyError(f"{path} is a symlink not owned by root")
        check_executable(os.path.realpath(path), lstat, read_head)
        return
    check_trusted_path(path, lstat)
    if not stat.S_ISREG(st.st_mode):
        raise PolicyError(f"{path} is not a regular file")
    if not st.st_mode & stat.S_IXUSR:
        raise PolicyError(f"{path} is not executable")

    if read_head is None:
        def read_head(p):
            with open(p, "rb") as f:
                return f.read(256)
    head = read_head(path)
    if head.startswith(b"#!"):
        line = head[2:].split(b"\n", 1)[0].decode("utf-8", "replace").strip()
        interpreter = line.split()[0] if line else ""
        if os.path.basename(interpreter) in FORBIDDEN_EXECUTABLES or os.path.basename(interpreter) == "env":
            raise PolicyError(f"{path} is a script run by {interpreter}, which can run arbitrary code from its environment")
        check_executable(interpreter, lstat, read_head)


def read_protected_json(path: Path, enforce_ownership: bool = True) -> dict:
    """Reads a JSON file only if it, and every directory above it, are root-controlled."""
    if enforce_ownership:
        check_trusted_path(str(path.parent))

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        raise PolicyError(f"cannot open {path} safely: {e}") from e
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PolicyError(f"{path} is not a regular file")
        if enforce_ownership:
            _check_owner_and_mode(st, str(path))
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            fd = -1
            return json.load(f)
    except json.JSONDecodeError as e:
        raise PolicyError(f"{path} is not valid JSON: {e}") from e
    finally:
        if fd >= 0:
            os.close(fd)


def parse_profiles(data: dict) -> Dict[str, Action]:
    if data.get("schema") != "suit.profiles.v1":
        raise PolicyError("profiles: expected schema suit.profiles.v1")

    actions: Dict[str, Action] = {}
    for name, spec in (data.get("actions") or {}).items():
        if not name or set(name) - ACTION_NAME_CHARS:
            raise PolicyError(f"profiles: invalid action name {name!r}")
        argv = spec.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
            raise PolicyError(f"profiles: {name}: argv must be a non-empty list of non-empty strings")
        exe = argv[0]
        if not exe.startswith("/") or "/../" in exe or exe.endswith("/.."):
            raise PolicyError(f"profiles: {name}: argv[0] must be an absolute path without '..'")
        if os.path.basename(exe) in FORBIDDEN_EXECUTABLES:
            raise PolicyError(f"profiles: {name}: {exe} can run arbitrary code and is not allowed")
        for arg in argv[1:]:
            if any(ch in arg for ch in "*?[") or "\x00" in arg:
                raise PolicyError(f"profiles: {name}: arguments must be literal, found {arg!r}")
        actions[name] = Action(name=name, argv=tuple(argv), description=str(spec.get("description", "")))
    return actions


def parse_eligibility(data: dict, actions: Dict[str, Action]) -> Dict[int, Eligibility]:
    if data.get("schema") != "suit.eligibility.v1":
        raise PolicyError("eligibility: expected schema suit.eligibility.v1")

    result: Dict[int, Eligibility] = {}
    for entry in data.get("users") or []:
        uid = entry.get("uid")
        if not isinstance(uid, int) or uid <= 0:
            raise PolicyError(f"eligibility: invalid uid {uid!r} (root cannot be made eligible)")
        names: List[str] = entry.get("actions") or []
        unknown = [n for n in names if n not in actions]
        if unknown:
            raise PolicyError(f"eligibility: uid {uid}: unknown actions {unknown}")
        max_seconds = entry.get("max_duration_seconds")
        if not isinstance(max_seconds, int) or not 60 <= max_seconds <= MAX_GRANT_SECONDS:
            raise PolicyError(f"eligibility: uid {uid}: max_duration_seconds must be 60..{MAX_GRANT_SECONDS} (CAG-INV-3)")
        result[uid] = Eligibility(uid=uid, actions=frozenset(names), max_duration_seconds=max_seconds)
    return result


def load(policy_dir: Path = POLICY_DIR, enforce_ownership: bool = True) -> Tuple[Dict[str, Action], Dict[int, Eligibility], frozenset]:
    """Loads and validates both policy files.

    Returns:
        The actions, the eligibility map, and the set of approver UIDs.
    """
    profiles = parse_profiles(read_protected_json(policy_dir / "profiles.json", enforce_ownership))
    if enforce_ownership:
        for action in profiles.values():
            try:
                check_executable(action.argv[0])
            except (PolicyError, OSError) as e:
                raise PolicyError(f"profiles: {action.name}: {e}") from e
    elig_data = read_protected_json(policy_dir / "eligibility.json", enforce_ownership)
    eligibility = parse_eligibility(elig_data, profiles)
    approvers = elig_data.get("approvers") or []
    if not all(isinstance(a, int) and a >= 0 for a in approvers):
        raise PolicyError("eligibility: approvers must be a list of uids")
    return profiles, eligibility, frozenset(approvers)


def verify_installation(module_files, interpreter: str) -> None:
    """Refuses to run unless the broker's own code path is root-controlled.

    The broker is only as trustworthy as the files it executes: its Python
    interpreter and every module it imported. Install-time ownership can
    drift, so it is checked on every run.
    """
    check_executable(interpreter)
    for path in module_files:
        check_trusted_path(os.path.realpath(path))
