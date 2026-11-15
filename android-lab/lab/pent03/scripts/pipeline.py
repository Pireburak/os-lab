#!/usr/bin/env python3
"""End-to-end PENT-03 orchestrator: boot -> frida -> CA -> proxy -> unpin.

Runs the headless analysis pipeline against a lab emulator, logging every step
so a run is reproducible and auditable (PENT-14 style per-step log). Order:

1. **scope** — refuse anything that isn't a lab emulator + lab package.
2. **boot** — wait for the emulator to finish booting.
3. **frida** — deploy and start ``frida-server`` for the device ABI.
4. **ca** — install the mitmproxy CA into the system trust store.
5. **proxy** — point the device's global HTTP proxy at the mitmproxy host.
6. **unpin** — run objection's universal SSL-pinning bypass on the target app.

``plan()`` is a pure function (used in tests). ``--dry-run`` prints the plan and
the exact commands without touching a device.
"""
from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass, field

import adb
import deploy_frida
import install_ca
import report as report_mod
import scope
import sslpinning_bypass

#: host:port the emulator reaches mitmproxy on (10.0.2.2 == host loopback).
DEFAULT_PROXY = "10.0.2.2:8080"

STEPS = ("scope", "boot", "frida", "ca", "proxy", "unpin")


def plan(*, skip: tuple[str, ...] = ()) -> list[str]:
    """Return the ordered list of steps that will run, minus ``skip``."""
    return [s for s in STEPS if s not in skip]


def set_proxy_command(proxy: str) -> list[str]:
    """adb args that set the device-wide HTTP proxy to ``proxy``."""
    return ["settings", "put", "global", "http_proxy", proxy]


def clear_proxy_command() -> list[str]:
    """adb args that clear the device-wide HTTP proxy."""
    return ["settings", "put", "global", "http_proxy", ":0"]


@dataclass
class StepResult:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class PipelineReport:
    package: str
    serial: str
    steps: list[StepResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(s.ok for s in self.steps)

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.steps.append(StepResult(name, ok, detail))
        mark = "ok " if ok else "FAIL"
        print(f"  [{mark}] {name}: {detail}")


def run_pipeline(
    package: str,
    *,
    serial: str = "emulator-5554",
    proxy: str = DEFAULT_PROXY,
    frida_version: str = deploy_frida.DEFAULT_FRIDA_VERSION,
    ca_path: str | None = None,
    skip: tuple[str, ...] = (),
    sleep=time.sleep,
) -> PipelineReport:
    """Execute the pipeline against a device. Returns a :class:`PipelineReport`."""
    report = PipelineReport(package=package, serial=serial)
    steps = plan(skip=skip)
    proxy_host = proxy.rsplit(":", 1)[0]

    # 1. scope — always enforced, never skippable.
    scope.assert_in_scope(serial=serial, package=package, proxy_host=proxy_host)
    report.add("scope", True, f"{serial} / {package} / {proxy_host}")

    if "boot" in steps:
        adb.wait_for_boot(serial, sleep=sleep)
        report.add("boot", True, "emulator boot_completed")

    if "frida" in steps:
        ver = deploy_frida.deploy(serial, version=frida_version)
        report.add("frida", True, f"frida-server {ver} running")

    if "ca" in steps:
        remote = install_ca.install(serial, ca_path)
        report.add("ca", True, f"mitmproxy CA at {remote}")

    if "proxy" in steps:
        adb.shell(serial, *set_proxy_command(proxy))
        report.add("proxy", True, f"global http_proxy -> {proxy}")

    if "unpin" in steps:
        code = sslpinning_bypass.bypass(package, serial=serial)
        report.add("unpin", code == 0, f"objection exit={code}")

    return report


def _print_dry_run(package: str, serial: str, proxy: str, skip: tuple[str, ...]) -> None:
    steps = plan(skip=skip)
    print(f"DRY RUN — pipeline for {package} on {serial}")
    print(f"  steps: {' -> '.join(steps)}")
    print("  commands that would run:")
    if "frida" in steps:
        print(f"    deploy_frida.deploy({serial!r}, version={deploy_frida.DEFAULT_FRIDA_VERSION!r})")
    if "ca" in steps:
        print(f"    install_ca.install({serial!r})")
    if "proxy" in steps:
        print(f"    adb -s {serial} shell {' '.join(set_proxy_command(proxy))}")
    if "unpin" in steps:
        print("    " + " ".join(sslpinning_bypass.objection_argv(package, serial=serial)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the PENT-03 analysis pipeline.")
    parser.add_argument("package", help="target application id (lab-owned)")
    parser.add_argument("-s", "--serial", default="emulator-5554")
    parser.add_argument("--proxy", default=DEFAULT_PROXY)
    parser.add_argument("--frida-version", default=deploy_frida.DEFAULT_FRIDA_VERSION)
    parser.add_argument("--ca", default=None)
    parser.add_argument(
        "--skip", default="", help="comma-separated steps to skip (boot,frida,ca,proxy,unpin)"
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--report",
        nargs="?",
        const="runs",
        default=None,
        metavar="DIR",
        help="write a timestamped JSON+Markdown run report into DIR (default: runs/)",
    )
    args = parser.parse_args(argv)
    skip = tuple(s.strip() for s in args.skip.split(",") if s.strip())

    try:
        scope.assert_in_scope(
            serial=args.serial,
            package=args.package,
            proxy_host=args.proxy.rsplit(":", 1)[0],
        )
    except scope.ScopeError as exc:
        print(f"OUT OF SCOPE: {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        _print_dry_run(args.package, args.serial, args.proxy, skip)
        return 0

    try:
        report = run_pipeline(
            args.package,
            serial=args.serial,
            proxy=args.proxy,
            frida_version=args.frida_version,
            ca_path=args.ca,
            skip=skip,
        )
    except (scope.ScopeError, adb.AdbError, deploy_frida.FridaDeployError,
            install_ca.CaInstallError, sslpinning_bypass.BypassError) as exc:
        print(f"pipeline failed: {exc}", file=sys.stderr)
        return 1

    if args.report:
        json_path, md_path = report_mod.write_report(report, args.report)
        print(f"  [report] {json_path}")
        print(f"  [report] {md_path}")

    print()
    if report.ok:
        print("pipeline complete — point mitmproxy at the flows and start analysis.")
        return 0
    print("pipeline finished with failures.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
