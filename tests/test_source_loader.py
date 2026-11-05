from pathlib import Path
from zipfile import ZipFile

from reviewer.source_loader import load_source


def test_folder_loads_supported_files(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.ts").write_text("const x = 1;\n", encoding="utf-8")
    (tmp_path / ".env").write_text("API_KEY=do-not-load", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("ignore me", encoding="utf-8")
    result = load_source(tmp_path)
    assert [f.path for f in result.files] == ["src/index.ts"]
    assert result.files[0].line_count == 1


def test_zip_loads_code_and_rejects_traversal(tmp_path: Path):
    archive_path = tmp_path / "sample.zip"
    with ZipFile(archive_path, "w") as archive:
        archive.writestr("src/main.tsx", "export default function App() {}")
        archive.writestr("../bad.sql", "SELECT 1;")
        archive.writestr(".env", "API_KEY=secret")
    result = load_source(archive_path)
    assert [f.path for f in result.files] == ["src/main.tsx"]
    assert any("unsafe ZIP entry" in text for text in result.skipped)


def test_binary_supported_extension_skipped(tmp_path: Path):
    (tmp_path / "bad.py").write_bytes(b"a\x00b")
    result = load_source(tmp_path)
    assert not result.files
    assert any("binary" in text for text in result.skipped)
