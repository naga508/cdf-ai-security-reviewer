"""Conservative exact-evidence citation repair; all tests offline."""

from reviewer.gemini_analyzer import Finding, _realign_citation, _verify
from reviewer.source_loader import SourceFile


def source(content: str) -> SourceFile:
    return SourceFile(path="src/demo.tsx", content=content, size_bytes=len(content), line_count=len(content.splitlines()))


def finding(line: int, evidence: str) -> Finding:
    return Finding(
        file="src/demo.tsx", line=line, title="Potential XSS",
        severity="HIGH", confidence="HIGH", cwe="CWE-79", evidence=evidence,
        explanation="Review untrusted comment HTML", recommendation="Escape comment data",
        secure_code="<div>{comment.text}</div>",
    )


def test_repairs_one_line_offset_for_xss():
    src = source("  <div\n    dangerouslySetInnerHTML={{\n      __html: comment.text,\n    }}\n  />\n")
    original = finding(2, "__html: comment.text,")
    corrected, note = _realign_citation(original, {src.path: src})
    assert original.line == 2  # model output preserved
    assert corrected.line == 3
    assert note and "from line 2 to 3" in note
    assert _verify(corrected, {src.path: src}) is None


def test_rejects_hallucinated_code():
    src = source("console.log('ok');\n")
    original = finding(1, "dangerouslySetInnerHTML")
    corrected, note = _realign_citation(original, {src.path: src})
    assert corrected.line == 1 and note is None
    assert _verify(corrected, {src.path: src}) is not None


def test_ambiguous_nearby_match_does_not_autocorrect():
    src = source("x();\n.update(changes)\ny();\n.update(changes)\n")
    original = finding(3, ".update(changes)")
    corrected, note = _realign_citation(original, {src.path: src})
    assert corrected.line == 3 and note is None
    assert _verify(corrected, {src.path: src}) is not None


def test_preserves_exact_valid_citation():
    src = source("dangerouslySetInnerHTML={{\n")
    original = finding(1, "dangerouslySetInnerHTML")
    corrected, note = _realign_citation(original, {src.path: src})
    assert corrected is original and note is None
