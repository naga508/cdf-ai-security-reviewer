"""CLI entry point. Stage 1: source ingestion only."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .source_loader import load_source


def main() -> None:
    parser = argparse.ArgumentParser(description="CDF AI Security Reviewer")
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect", help="List readable code files; does not run AI analysis")
    inspect.add_argument("--path", required=True, help="Source directory or ZIP file")
    inspect.add_argument("--manifest", help="Optional JSON manifest output path")
    args = parser.parse_args()

    if args.command == "inspect":
        result = load_source(args.path)
        print(f"Input: {result.input_path}")
        print(f"Loaded {len(result.files)} source files")
        for item in result.files:
            print(f"  {item.path}: {item.line_count} lines, {item.size_bytes} bytes")
        print(f"Skipped {len(result.skipped)} supported-source candidates")
        for message in result.skipped[:20]:
            print(f"  SKIPPED: {message}")
        if args.manifest:
            manifest_path = Path(args.manifest)
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(json.dumps({
                "input": result.input_path,
                "files": [
                    {"path": f.path, "lines": f.line_count, "bytes": f.size_bytes}
                    for f in result.files
                ],
                "skipped": result.skipped,
                "status": "SOURCE_INGESTION_ONLY_NO_VULNERABILITY_ASSESSMENT",
            }, indent=2), encoding="utf-8")
            print(f"Manifest saved: {manifest_path}")
        print("Status: source ingestion complete; Gemini security analysis is not yet implemented.")


if __name__ == "__main__":
    main()
