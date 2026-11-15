#!/usr/bin/env python3
"""Lab-only scope guard for the PENT-03 Android pipeline.

Every destructive or network-touching action in this lab routes through
``assert_in_scope`` first. The guard refuses to act on anything that is not an
isolated lab emulator / lab package, enforcing the authorization-only rule in
code rather than in a README nobody reads.

What counts as "in scope":

* **Devices / serials** — local emulators (``emulator-5554``), loopback adb
  (``127.0.0.1:5555``), and the Android emulator NAT range (``10.0.2.0/24``).
  Physical USB serials are refused by default; opt in with ``OSLAB_EXTRA_SERIALS``.
* **Packages** — the bundled lab targets plus anything matching the lab
  prefixes (``com.securebank.``, ``org.oslab.``, ``com.lab.``). Extend with
  ``OSLAB_EXTRA_PACKAGES``.
* **Proxy / MITM hosts** — loopback and the emulator's host-loopback alias
  ``10.0.2.2`` only.

Environment escape hatches are intentionally explicit and comma-separated so an
instructor can widen scope for a known lab without editing code:

    OSLAB_EXTRA_SERIALS="emulator-5556,192.168.56.101:5555"
    OSLAB_EXTRA_PACKAGES="com.myorg.testapp"
    OSLAB_EXTRA_PROXY_HOSTS="mitmproxy"

Usage (library)::

    from scope import assert_in_scope, ScopeError
    assert_in_scope(serial="emulator-5554", package="com.securebank.mobile")

Usage (CLI)::

    python3 scope.py --serial emulator-5554 --package com.securebank.mobile
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import sys

# --- Static lab allowlists -------------------------------------------------

#: Emulator / loopback serials that are always considered lab devices.
LAB_SERIAL_EXACT = frozenset(
    {
        "emulator-5554",
        "emulator-5556",
        "emulator-5558",
        "127.0.0.1:5555",
        "localhost:5555",
    }
)

#: adb host:port serials whose host lies in one of these nets are in scope.
LAB_NETS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.2.0/24"),  # Android emulator NAT
)

#: Package name prefixes that denote lab-owned apps.
LAB_PACKAGE_PREFIXES = (
    "com.securebank.",
    "org.oslab.",
    "com.lab.",
    "com.example.",
)

#: Hosts a lab proxy / MITM endpoint may legitimately be.
LAB_PROXY_HOSTS = frozenset({"127.0.0.1", "localhost", "10.0.2.2", "::1"})


class ScopeError(RuntimeError):
    """Raised when a target is outside the authorized lab scope."""


def _extra(env_name: str) -> frozenset[str]:
    raw = os.environ.get(env_name, "")
    return frozenset(x.strip() for x in raw.split(",") if x.strip())


def serial_in_scope(serial: str) -> bool:
    """Return True if ``serial`` is an authorized lab device."""
    if not serial:
        return False
    serial = serial.strip()
    if serial in LAB_SERIAL_EXACT or serial in _extra("OSLAB_EXTRA_SERIALS"):
        return True
    if serial.startswith("emulator-"):
        return True
    host = serial.rsplit(":", 1)[0] if ":" in serial else serial
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(addr in net for net in LAB_NETS)


def package_in_scope(package: str) -> bool:
    """Return True if ``package`` is a lab-owned application id."""
    if not package:
        return False
    package = package.strip()
    if package in _extra("OSLAB_EXTRA_PACKAGES"):
        return True
    return any(package.startswith(p) for p in LAB_PACKAGE_PREFIXES)


def proxy_host_in_scope(host: str) -> bool:
    """Return True if ``host`` is an allowed lab proxy / MITM endpoint."""
    if not host:
        return False
    host = host.strip()
    if host in LAB_PROXY_HOSTS or host in _extra("OSLAB_EXTRA_PROXY_HOSTS"):
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.is_loopback or any(addr in net for net in LAB_NETS)


def assert_in_scope(
    *,
    serial: str | None = None,
    package: str | None = None,
    proxy_host: str | None = None,
) -> None:
    """Raise :class:`ScopeError` unless every supplied target is in scope.

    Only the arguments you pass are checked, so the same guard works for a
    device-only action (frida deploy) and a full run (device + package + proxy).
    """
    problems: list[str] = []
    if serial is not None and not serial_in_scope(serial):
        problems.append(
            f"device {serial!r} is not a recognized lab emulator "
            f"(set OSLAB_EXTRA_SERIALS to widen scope for a known lab)"
        )
    if package is not None and not package_in_scope(package):
        problems.append(
            f"package {package!r} is not a lab-owned app "
            f"(set OSLAB_EXTRA_PACKAGES to widen scope for a known lab)"
        )
    if proxy_host is not None and not proxy_host_in_scope(proxy_host):
        problems.append(f"proxy host {proxy_host!r} is not a loopback/lab host")
    if problems:
        raise ScopeError(
            "refusing to act outside the authorized lab scope:\n  - "
            + "\n  - ".join(problems)
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a target against lab scope.")
    parser.add_argument("--serial")
    parser.add_argument("--package")
    parser.add_argument("--proxy-host")
    args = parser.parse_args(argv)
    try:
        assert_in_scope(
            serial=args.serial,
            package=args.package,
            proxy_host=args.proxy_host,
        )
    except ScopeError as exc:
        print(f"OUT OF SCOPE: {exc}", file=sys.stderr)
        return 2
    print("in scope")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
