"""Report chain stays Unicode-safe regardless of the process locale/encoding.

Regression: on Windows with a non-UTF8 default (cp1252), writing
report.md / report.draft.md / findings.json used to crash with
UnicodeEncodeError because the banner carries U+26A0. Every write/read
in the report chain is now explicit UTF-8.
"""
import hackingtool.ai_report as ai_report
import hackingtool.engagement as engagement
import hackingtool.report as report
from hackingtool.findings import Finding, load_findings, save_findings


def _root(tmp_path, monkeypatch):
    monkeypatch.setattr(engagement, "ENGAGEMENTS_ROOT", tmp_path)


def test_report_chain_roundtrips_unicode(tmp_path, monkeypatch):
    _root(tmp_path, monkeypatch)
    uni = "caf\u00e9 \u26a0 \u4e2d\u6587 \U0001f680"
    e = engagement.create("acme", targets=["a.example.com"])
    save_findings(e.findings_file, [
        Finding("vulnerability", "https://a.example.com/.git/",
                f"Exposed .git {uni}", "high", "nuclei",
                {"note": uni}, f"raw {uni}", "T"),
    ])
    assert uni in load_findings(e.findings_file)[0].name

    text = report.generate_report(e).read_text(encoding="utf-8")
    assert uni in text

    monkeypatch.setattr(ai_report, "ask", lambda p: f"Summary {uni}")
    draft = ai_report.draft_report(e).read_text(encoding="utf-8")
    assert uni in draft and "\u26a0" in draft
