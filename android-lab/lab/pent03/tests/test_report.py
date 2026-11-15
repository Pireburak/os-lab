"""Run-report writer tests — renderers are pure; writing uses tmp_path."""
import datetime as dt
import json
from dataclasses import dataclass, field

import report


@dataclass
class _Step:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class _Report:
    package: str
    serial: str
    steps: list = field(default_factory=list)

    @property
    def ok(self):
        return all(s.ok for s in self.steps)


def _sample():
    return _Report(
        package="com.securebank.mobile",
        serial="emulator-5554",
        steps=[
            _Step("scope", True, "ok"),
            _Step("frida", True, "16.5.9"),
            _Step("unpin", False, "exit=1"),
        ],
    )


def test_utc_stamp_format():
    stamp = report.utc_stamp(dt.datetime(2026, 11, 15, 10, 22, 33, tzinfo=dt.timezone.utc))
    assert stamp == "20261115T102233Z"


def test_report_to_dict_shape():
    d = report.report_to_dict(_sample())
    assert d["task"] == "PENT-03"
    assert d["package"] == "com.securebank.mobile"
    assert d["ok"] is False
    assert [s["name"] for s in d["steps"]] == ["scope", "frida", "unpin"]


def test_render_markdown_has_table_and_status():
    md = report.render_markdown(report.report_to_dict(_sample()))
    assert "# PENT-03 run" in md
    assert "failed" in md
    assert "| scope | PASS |" in md
    assert "| unpin | FAIL |" in md


def test_write_report_creates_both_files(tmp_path):
    now = dt.datetime(2026, 11, 15, 10, 22, 33, tzinfo=dt.timezone.utc)
    json_path, md_path = report.write_report(_sample(), str(tmp_path), now=now)
    assert json_path.endswith("20261115T102233Z.json")
    assert md_path.endswith("20261115T102233Z.md")
    data = json.loads(open(json_path, encoding="utf-8").read())
    assert data["serial"] == "emulator-5554"
    assert "PENT-03 run" in open(md_path, encoding="utf-8").read()


def test_main_renders_existing_json(tmp_path, capsys):
    now = dt.datetime(2026, 11, 15, 10, 22, 33, tzinfo=dt.timezone.utc)
    json_path, _ = report.write_report(_sample(), str(tmp_path), now=now)
    rc = report.main([json_path])
    assert rc == 0
    assert "PENT-03 run" in capsys.readouterr().out
