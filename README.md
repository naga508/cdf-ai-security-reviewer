# CDF AI Security Reviewer — Find · Fix · Fortify

A Gemini-powered, static AI-assisted security code reviewer built for the CDF Intelligent Code Security Challenge. It accepts a **local source directory or ZIP archive**, reads eligible source files without executing them, asks Gemini to identify potential vulnerabilities and recommend fixes, validates source citations, and generates **Markdown and JSON security assessments**.

## Features

- **Ingest:** Local folder or ZIP; selective source discovery, line numbering, size limits, and exclusion of common dependency, hidden, and sensitive files.
- **Find:** Gemini security review for injection, XSS, authorization, access-control, and data-exposure concerns.
- **Deep review:** Optional second Gemini pass concentrating on authentication, authorization, and row-level security (RLS).
- **Fix:** Model-generated mitigation guidance and illustrative safer code snippets.
- **Validate:** Verify the cited file and quoted evidence against the source; conservatively adjust a nearby citation only when the quote matches uniquely. Keep rejected findings in a distinct **Unverified candidates** section for manual review.
- **Fortify:** Export `report.json` and `report.md` with findings, severity counts, executive summary, assessment, coverage, and limitations.
- **Test:** Unit tests with stubbed Gemini responses (no API charges for unit tests).

## Setup

Requirements: Python 3.10+, Git, and a Gemini API key for live scans.

From this repository root, create and activate an environment:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
```

Create a local `.env` file (never commit it):

```dotenv
GEMINI_API_KEY=YOUR_OWN_API_KEY
GEMINI_MODEL=gemini-3.5-flash-lite
```

Get a key from Google AI Studio. Verify that your key is ignored by Git:

```powershell
git check-ignore .env
```

## Commands

Use `python` from your active virtual environment, or replace `python` in the examples with `.\.venv\Scripts\python.exe`.

```powershell
# Inspect a source folder without sending any content to Gemini
python -m reviewer inspect --path "C:\path\to\source-folder" --manifest reports\source-manifest.json

# Analyze a folder with two Gemini review passes (subject to service availability)
python -m reviewer scan --path "C:\path\to\source-folder" --model gemini-3.5-flash-lite --output reports\security-review

# Analyze a ZIP archive
python -m reviewer scan --path "C:\path\to\source-code.zip" --model gemini-3.5-flash-lite --output reports\zip-review

# Reduce API usage by disabling the optional second pass
python -m reviewer scan --path "C:\path\to\source-folder" --model gemini-3.5-flash-lite --no-deep-review

# List available Gemini models for your key
python -m reviewer models
```

The `--max-batches` option limits how many source batches are submitted. A failed API call, skipped source, or batch cap may cause **partial/inconclusive** coverage; do not present such output as a complete security assessment.

Reports are written beneath `reports/`, which is Git-ignored by default. Review generated reports before deciding which example to share publicly.

## How it works

1. Load permitted source code from a folder or ZIP without executing it.
2. Preserve file paths and numbered source lines, and group source into bounded Gemini requests.
3. Ask Gemini for structured candidate vulnerabilities, rationales, and proposed fixes.
4. Optionally make a second review pass for authorization/RLS issues.
5. Verify cited evidence mechanically and separate unsupported citations from accepted findings.
6. Generate a Markdown/JSON review with a coverage summary, potential risks, remediation suggestions, and explicit uncertainty.

## Example run and limitations

In one local test against the organizer-supplied **CDF TaskFlow** sample (12 eligible files), Gemini 3.5 Flash-Lite completed two review passes and returned four source-referenced potential findings: SQL injection, task-update authorization, task-update mass assignment, and service-role profile retrieval. The report also retained an XSS candidate with a rejected model citation for manual verification. **These are review candidates, not demonstrated exploits.** Results may vary between API calls.

Evidence verification confirms that quoted code is present. It **does not** establish exploitability, prove every issue has been detected, or guarantee that a suggested fix compiles or addresses all authorization requirements. Severity is AI-assigned and requires human review. Related findings from the same function may overlap.

Temporary Gemini HTTP 503 errors can occur. The scanner supports bounded retry behavior but cannot guarantee service availability; review the warnings and coverage status after each run.

## Safety and responsible use

Review only repositories you are permitted to analyze. The scanner does not execute untrusted source, but uploading source to the Gemini API still sends that content to an external service. Do not submit proprietary, confidential, regulated, or sensitive code without authorization. File filtering and redaction are defensive measures, **not a guarantee** that every secret is detected. Never commit `.env`, API keys, or private credentials.

## Attribution

- Challenge materials and CDF TaskFlow vulnerable test application: CDF hackathon organizers (not authored by this project).
- LLM security analysis: Google Gemini API; model identified in each report.
- Python dependencies: see `requirements.txt`.

This tool is a prototype for security-review assistance, not a substitute for a professional audit, code-owner review, or runtime validation.
