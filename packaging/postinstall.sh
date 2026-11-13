#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
# Runs as root after the package's files are in place.
set -e
add_group() {
    getent group "$1" >/dev/null && return 0
    if command -v groupadd >/dev/null; then groupadd -r "$1"; else addgroup -S "$1"; fi
}
add_group suit-eligible
add_group suit-approvers
install -d -m 0700 -o root -g root /var/lib/suit
# A sudoers drop-in with a syntax error breaks sudo for everyone: check it,
# and remove it rather than leave sudo unusable.
if ! visudo -cf /etc/sudoers.d/suit >/dev/null; then
    echo "suit-linux: /etc/sudoers.d/suit failed visudo; removed it" >&2
    rm -f /etc/sudoers.d/suit
    exit 1
fi
cat <<'MSG'
SUIT for Linux is installed with an empty policy, so it grants nothing yet.
  1. Define actions in /etc/suit/profiles.json and users in /etc/suit/eligibility.json
     (examples: /usr/share/doc/suit-linux/).
  2. Add requesters to suit-eligible and approvers to suit-approvers.
  3. As root, run: suit doctor
MSG
