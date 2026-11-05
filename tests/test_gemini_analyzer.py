"""Offline tests: these tests do not consume Gemini quota."""

from pathlib import Path

from reviewer.gemini_analyzer import Finding, _batches, _redact_line, _verify, save_report
from reviewer.source_loader import LoadResult, SourceFile


def test_evidence_on_exact_line():
    source = SourceFile(path="src/test.ts", content="const a = 1;\nconst b = 2;\n", size_bytes=26, line_count=2)
    item = Finding(file="src/test.ts", line=2, title="example", severity="LOW", confidence="LOW",
                   cwe="N/A", evidence="const b = 2;", explanation="test",
                   recommendation="test", secure_code="test")
    assert _verify(item, {source.path: source}) is None
    assert _verify(item.model_copy(update={"line": 1}), {source.path: source}) is not None


def test_batches_keep_source_path_and_line_numbers():
    source = SourceFile(path="a.sql", content="SELECT 1;\nSELECT 2;", size_bytes=19, line_count=2)
    batches = _batches(LoadResult(input_path="sample", files=[source], skipped=[]))
    assert "FILE: a.sql" in batches[0][0]
    assert "2: SELECT 2;" in batches[0][0]
    assert batches[0][1] == {"a.sql"}


def test_basic_redaction():
    assert "some_secret_value" not in _redact_line('api_key = "some_secret_value"')


def test_json_and_markdown_reports(tmp_path: Path):
    from reviewer.gemini_analyzer import ScanOutput
    result = ScanOutput(model="test-model", input_path="sample", loaded_files=1,
                        analyzed_files=["a.sql"], findings=[], rejected_findings=[],
                        skipped_files=[], warnings=[], api_calls=1, complete_coverage=True)
    json_path, md_path = save_report(result, tmp_path)
    assert json_path.is_file() and md_path.is_file()
    assert '"model": "test-model"' in json_path.read_text(encoding="utf-8")
    assert "does not prove" in md_path.read_text(encoding="utf-8")
