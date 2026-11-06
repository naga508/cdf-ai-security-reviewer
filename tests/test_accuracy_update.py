"""Offline behavioral regression tests: no Gemini API key or paid calls required."""

import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

from reviewer.gemini_analyzer import (
    Finding, Review, _focused_context, _window, save_report, scan_with_gemini,
)
from reviewer.source_loader import LoadResult, SourceFile


@pytest.fixture(autouse=True)
def fake_genai_types(monkeypatch):
    """Only the request config is needed by the stub API client."""
    google = types.ModuleType("google")
    genai = types.ModuleType("google.genai")
    genai.types = SimpleNamespace(GenerateContentConfig=lambda **kw: kw)
    google.genai = genai
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.genai", genai)


def make_source(path, content):
    return SourceFile(path=path, content=content, size_bytes=len(content.encode()), line_count=len(content.splitlines()))


def issue(path, line, evidence, title="Missing authorization", cwe="CWE-862"):
    return Finding(
        file=path, line=line, title=title, severity="HIGH", confidence="MEDIUM",
        cwe=cwe, evidence=evidence,
        explanation="A caller-supplied ID may be used without an ownership check; verify deployment controls.",
        recommendation="Verify user ownership and enforce row-level security.",
        secure_code="// verify ownership before update",
    )


class StubModel:
    def __init__(self, sequence):
        self.sequence = iter(sequence)
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        outcome = next(self.sequence)
        if isinstance(outcome, Exception):
            raise outcome
        return SimpleNamespace(parsed=Review(findings=outcome), text=None)


def test_focused_pass_discovers_second_issue_and_preserves_source_context(tmp_path):
    ts_path = "supabase/functions/update-task/index.ts"
    sql_path = "supabase/migrations/002_access_policies.sql"
    ts = make_source(ts_path, 'const id = req.taskId;\nconst client = createClient("SERVICE_ROLE");\nclient.update(changes);\n')
    sql = make_source(sql_path, 'CREATE POLICY task_read ON tasks FOR SELECT USING (true);\n')
    loaded = LoadResult(input_path="/local/unimportant/vulnerable-app", files=[ts, sql], skipped=[])
    a = issue(ts_path, 3, "client.update(changes)")
    b = issue(sql_path, 1, "USING (true)", title="Overly permissive read policy", cwe="CWE-284")
    client = SimpleNamespace(models=StubModel([[a], [b]]))

    output = scan_with_gemini(loaded, client, model="fake")
    assert output.api_calls == 2
    assert output.review_passes_completed == 2
    assert output.complete_coverage
    assert len(output.findings) == 2
    assert "2: const client" in output.evidence_windows[(a.file, a.line, a.cwe)]
    assert "Second independent security pass" in client.models.calls[1]["contents"]

    json_path, md_path = save_report(output, tmp_path)
    markdown = md_path.read_text(encoding="utf-8")
    assert "## Executive summary" in markdown
    assert "Overall assessment" in markdown
    assert "## Severity summary" in markdown
    assert "Source evidence and surrounding lines" in markdown
    assert "C:\\Users" not in markdown
    assert '"source_context"' in json_path.read_text(encoding="utf-8")


def test_deduplicates_same_cwe_nearby_line_from_second_pass():
    path = "supabase/functions/update-task/index.ts"
    source = make_source(path, "const user = x;\nclient.update(changes);\nclient.update(changes);\n")
    first = issue(path, 2, "client.update(changes)")
    second = issue(path, 3, "client.update(changes)", title="Authorization absent")
    client = SimpleNamespace(models=StubModel([[first], [second]]))
    result = scan_with_gemini(LoadResult("sample", [source], []), client, "fake")
    assert result.api_calls == 2
    assert len(result.findings) == 1


def test_transient_503_retries_and_recovers(monkeypatch):
    class TemporaryFailure(Exception):
        code = 503
    monkeypatch.setattr("reviewer.gemini_analyzer.time.sleep", lambda _: None)
    source = make_source("src/a.py", "print('ok')\n")
    client = SimpleNamespace(models=StubModel([TemporaryFailure("high demand"), []]))
    result = scan_with_gemini(LoadResult("sample", [source], []), client, "fake")
    assert result.complete_coverage
    assert result.api_calls == 1
    assert len(client.models.calls) == 2


def test_non_retryable_failure_is_incomplete():
    class InvalidArgument(Exception):
        code = 400
    source = make_source("src/a.py", "print('ok')\n")
    client = SimpleNamespace(models=StubModel([InvalidArgument("bad schema")]))
    result = scan_with_gemini(LoadResult("sample", [source], []), client, "fake")
    assert not result.complete_coverage
    assert result.api_calls == 0
    assert "HTTP 400" in result.warnings[0]


def test_rejects_hallucinated_location():
    source = make_source("src/example.py", "print('ok')\n")
    bad = issue("src/example.py", 1, "made-up-code")
    client = SimpleNamespace(models=StubModel([[bad]]))
    result = scan_with_gemini(LoadResult("sample", [source], []), client, "fake")
    assert not result.findings
    assert len(result.rejected_findings) == 1


def test_context_masks_secret_and_input_path_is_not_leaked(tmp_path: Path):
    source = make_source("src/credential.py", 'api_key = "this-is-not-a-real-key"\nprint(123)\n')
    assert "this-is-not-a-real-key" not in _window(source, 1)
    client = SimpleNamespace(models=StubModel([[]]))
    output = scan_with_gemini(LoadResult("/Users/example/private/repository", [source], []), client, "fake")
    _, md_path = save_report(output, tmp_path)
    assert "/Users/example/private" not in md_path.read_text(encoding="utf-8")


def test_focus_selects_relevant_files_only():
    relevant = make_source("supabase/migrations/policies.sql", "CREATE POLICY x USING (true);\n")
    ignored = make_source("src/main.tsx", "const Component = () => null;\n")
    loaded = LoadResult("sample", [relevant, ignored], [])
    context, included, count = _focused_context(loaded, {relevant.path, ignored.path})
    assert included == count == 1
    assert "FILE: supabase/migrations/policies.sql" in context
    assert "src/main.tsx" not in context
