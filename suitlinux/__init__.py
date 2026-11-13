# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
"""SUIT for Linux: just-in-time privileged operations through a local broker.

The trust boundary is deliberately small. A user never receives a sudo rule
for a real command. They receive the right to ask the broker, and the broker
runs one exact, root-owned command line on their behalf only while an
independently approved, unexpired, unrevoked grant exists.
"""

__version__ = "0.3.0b1"
