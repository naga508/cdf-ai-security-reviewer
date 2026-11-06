"""Rejected model citations remain visible without relaxing exact-evidence checks."""

from pathlib import Path
from reviewer.gemini_analyzer import Finding, Review, ScanOutput, save_report
from reviewer.source_loader import SourceFile


def test_report_exposes_unverified_candidates_separately(tmp_path: Path):
    result = ScanOutput(
        model="test", input_path="/private/user/vulnerable-app", loaded_files=1,
        analyzed_files=["src/demo.tsx"], findings=[],
        rejected_findings=["src/demo.tsx:2 (XSS): evidence does not match"],
        skipped_files=[], warnings=[], api_calls=1, complete_coverage=True,
        unverified_candidates=[{
            "file": "src/demo.tsx", "line": 2, "title": "Possible XSS",
            "reason": "evidence does not match the cited source line",
            "source_context": "   1: <div\n   2: dangerouslySetInnerHTML={{\n   3: __html: comment.text",
        }],
    )
    json_path, md_path = save_report(result, tmp_path)
    md = md_path.read_text(encoding="utf-8")
    assert "## Unverified candidates" in md
    assert "Possible XSS" in md
    assert "dangerouslySetInnerHTML" in md
    assert "NOT accepted" in md
    assert "**Findings requiring review:** 0" in md
    assert "private/user" not in md
    data = json_path.read_text(encoding="utf-8")
    assert '"unverified_candidates"' in data
    assert '"findings": []' in data


def test_unverified_schema_defaults_empty():
    o = ScanOutput(model="x", input_path="x", loaded_files=0, analyzed_files=[],
                   findings=[], rejected_findings=[], skipped_files=[], warnings=[],
                   api_calls=0, complete_coverage=False)
    assert o.unverified_candidates == []


def test_failed_gemini_citation_kept_separate_in_real_pipeline(monkeypatch, tmp_path):
    import sys
    import types
    from types import SimpleNamespace
    from reviewer.gemini_analyzer import scan_with_gemini
    from reviewer.source_loader import LoadResult
    fake_google = types.ModuleType("google")
    fake_genai = types.ModuleType("google.genai")
    fake_genai.types = SimpleNamespace(GenerateContentConfig=lambda **kw: kw)
    fake_google.genai = fake_genai
    monkeypatch.setitem(sys.modules, "google", fake_google)
    monkeypatch.setitem(sys.modules, "google.genai", fake_genai)

    source = SourceFile(
        path="src/TaskComments.tsx",
        content="<div\n  dangerouslySetInnerHTML={{\n    __html: comment.text,\n  }}\n/>",
        size_bytes=60, line_count=5,
    )
    mistaken = Finding(
        file=source.path, line=2, title="Possible XSS", severity="HIGH",
        confidence="HIGH", cwe="CWE-79",
        evidence="dangerouslySetInnerHTML={{ __html: comment.text }}",  # Not a real single source line
        explanation="Untrusted comment may become HTML", recommendation="Render as text",
        secure_code="<div>{comment.text}</div>",
    )
    class StubModels:
        def generate_content(self, **kwargs):
            return SimpleNamespace(parsed=Review(findings=[mistaken]), text=None)
    client = SimpleNamespace(models=StubModels())
    result = scan_with_gemini(LoadResult("sample", [source], []), client, "fake", deep_review=False)
    assert result.api_calls == 1
    assert result.complete_coverage
    assert not result.findings
    assert len(result.unverified_candidates) == 1
    assert "dangerouslySetInnerHTML={{" in result.unverified_candidates[0]["source_context"]
    json_file, md_file = save_report(result, tmp_path)
    assert "## Unverified candidates" in md_file.read_text(encoding="utf-8")
