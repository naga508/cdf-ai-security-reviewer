"""CDF AI Security Reviewer command-line entry point."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .source_loader import load_source


def main() -> None:
    parser = argparse.ArgumentParser(description="CDF AI Security Reviewer")
    commands = parser.add_subparsers(dest="command", required=True)

    inspect = commands.add_parser("inspect", help="List readable source files without AI analysis")
    inspect.add_argument("--path", required=True, help="Source directory or ZIP file")
    inspect.add_argument("--manifest", help="Optional JSON manifest output path")

    scan = commands.add_parser("scan", help="Run Gemini vulnerability discovery and save reports")
    scan.add_argument("--path", required=True, help="Source directory or ZIP file")
    scan.add_argument("--output", default="reports/security-review", help="Output directory")
    scan.add_argument("--model", help="Gemini model ID, overriding GEMINI_MODEL")
    scan.add_argument("--max-batches", type=int, default=10, help="Maximum code batches to analyze")
    scan.add_argument("--no-deep-review", action="store_true", help="Skip the second authorization/RLS review to reduce API usage")

    commands.add_parser("models", help="List models accessible to your Gemini API key")
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
        print("Status: source ingestion complete; no Gemini review performed.")
        return

    from dotenv import load_dotenv
    load_dotenv()
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or api_key == "PASTE_YOUR_ACTUAL_API_KEY_HERE":
        parser.error("GEMINI_API_KEY not found in .env")

    from google import genai
    client = genai.Client(api_key=api_key)
    try:
        if args.command == "models":
            print("Gemini models available to your API key:")
            for model in client.models.list():
                print("  " + str(model.name))
            return

        from .gemini_analyzer import save_report, scan_with_gemini
        model_name = args.model or os.getenv("GEMINI_MODEL") or "gemini-3.5-flash"
        loaded = load_source(args.path)
        print(f"Loaded {len(loaded.files)} source files; sending permitted source to Gemini ({model_name}).")
        result = scan_with_gemini(
            loaded, client, model_name, max_batches=args.max_batches,
            deep_review=not args.no_deep_review,
        )
        json_path, md_path = save_report(result, args.output)
        print(f"Findings requiring review: {len(result.findings)}")
        print(f"Gemini API calls completed: {result.api_calls}")
        print(f"Review passes completed: {result.review_passes_completed}")
        print(f"Source coverage: {'complete within loader limits' if result.complete_coverage else 'partial / indeterminate'}")
        print(f"JSON report: {json_path}")
        print(f"Markdown report: {md_path}")
        if result.warnings:
            for item in result.warnings:
                print(f"WARNING: {item}")
        if not result.complete_coverage:
            raise SystemExit(2)  # Keep the report, but signal incomplete analysis to scripts.
    finally:
        client.close()


if __name__ == "__main__":
    main()
