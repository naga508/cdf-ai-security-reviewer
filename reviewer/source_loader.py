"""Safe, non-executing source reader for authorized repositories.

This stage reads selected text files and records the coverage limits; it does
not establish that those files are secure or detect vulnerabilities.
"""

from __future__ import annotations

import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from zipfile import ZipFile, is_zipfile

SUPPORTED_SUFFIXES = frozenset({
    ".ts", ".tsx", ".js", ".jsx", ".sql", ".py", ".java", ".go",
    ".rs", ".cs", ".rb", ".php", ".c", ".cpp", ".h",
})
IGNORED_DIRS = frozenset({
    "node_modules", ".git", ".venv", "venv", "dist", "build", "coverage",
    "__pycache__", ".next", ".cache", "vendor", "target", "reports",
})
MAX_FILE_BYTES = 512_000
MAX_TOTAL_BYTES = 8_000_000
MAX_SOURCE_FILES = 300


@dataclass(frozen=True)
class SourceFile:
    path: str
    content: str
    size_bytes: int
    line_count: int


@dataclass(frozen=True)
class LoadResult:
    input_path: str
    files: list[SourceFile]
    skipped: list[str]


def _eligible(path_parts: tuple[str, ...]) -> bool:
    if not path_parts:
        return False
    # No hidden paths, dependency trees, local secrets, or unsupported files.
    if any(part.startswith(".") or part.lower() in IGNORED_DIRS for part in path_parts):
        return False
    filename = path_parts[-1].lower()
    if filename.startswith(("id_rsa", "id_ed25519", "credentials", "secrets", "secret_")):
        return False
    return PurePosixPath(filename).suffix.lower() in SUPPORTED_SUFFIXES


def _decode_source(path: str, raw: bytes) -> SourceFile:
    if b"\x00" in raw:
        raise ValueError("binary content")
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("non-UTF-8 text") from exc
    return SourceFile(
        path=path,
        content=content,
        size_bytes=len(raw),
        line_count=len(content.splitlines()),
    )


def load_source(path: str | Path) -> LoadResult:
    """Read code files from a local directory or ZIP without executing them.

    Returns an explicit skipped-file log rather than silently claiming complete
    coverage. ZIP members are streamed individually; ZIP-slip and symlinks are
    rejected, with uncompressed member sizes capped before reading.
    """
    source = Path(path).expanduser().resolve()
    if not source.exists():
        raise FileNotFoundError(f"Input path not found: {source}")
    files: list[SourceFile] = []
    skipped: list[str] = []
    total = 0

    def collect(name: str, data: bytes) -> None:
        nonlocal total
        if len(files) >= MAX_SOURCE_FILES:
            skipped.append(f"{name}: source file count limit ({MAX_SOURCE_FILES})")
            return
        if len(data) > MAX_FILE_BYTES:
            skipped.append(f"{name}: above per-file size limit")
            return
        if total + len(data) > MAX_TOTAL_BYTES:
            skipped.append(f"{name}: above total source size limit")
            return
        try:
            item = _decode_source(name, data)
        except ValueError as exc:
            skipped.append(f"{name}: {exc}")
            return
        total += len(data)
        files.append(item)

    if source.is_dir():
        for file in sorted(source.rglob("*")):
            if file.is_symlink() or not file.is_file():
                continue
            relative = file.relative_to(source)
            parts = relative.parts
            if not _eligible(parts):
                continue
            name = relative.as_posix()
            try:
                size = file.stat().st_size
                if size > MAX_FILE_BYTES:
                    skipped.append(f"{name}: above per-file size limit")
                    continue
                if total + size > MAX_TOTAL_BYTES:
                    skipped.append(f"{name}: above total source size limit")
                    continue
                collect(name, file.read_bytes())
            except OSError as exc:
                skipped.append(f"{name}: could not read ({type(exc).__name__})")
    elif source.is_file() and is_zipfile(source):
        with ZipFile(source) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                normalized = member.filename.replace("\\", "/")
                parts = PurePosixPath(normalized).parts
                name = "/".join(parts)
                file_mode = (member.external_attr >> 16) & 0xFFFF
                if (normalized.startswith("/") or normalized.startswith("//")
                    or not parts or ".." in parts or ":" in parts[0]
                    or "\x00" in normalized or stat.S_ISLNK(file_mode)):
                    skipped.append(f"{member.filename}: unsafe ZIP entry")
                    continue
                if not _eligible(parts):
                    continue
                if member.file_size > MAX_FILE_BYTES:
                    skipped.append(f"{name}: above per-file size limit")
                    continue
                if total + member.file_size > MAX_TOTAL_BYTES:
                    skipped.append(f"{name}: above total source size limit")
                    continue
                try:
                    with archive.open(member) as stream:
                        data = stream.read(MAX_FILE_BYTES + 1)
                    collect(name, data)
                except (OSError, RuntimeError, ValueError, EOFError) as exc:
                    skipped.append(f"{name}: could not read ({type(exc).__name__})")
    else:
        raise ValueError("Expected a local directory or a ZIP archive")

    return LoadResult(str(source), files, skipped)
