# CDF AI Security Reviewer — Find · Fix · Fortify

**Hackathon project — implementation in progress.** The security analysis engine has
not yet been implemented. This initial commit provides a working, non-executing
source-code intake stage for folders and ZIP files.

## Planned capabilities

1. Accept an authorized source-code directory or ZIP.
2. Read TypeScript, React TSX, JavaScript, SQL, and other source formats safely.
3. Use Google Gemini to identify candidate security vulnerabilities (coming next).
4. Verify file paths, line numbers, evidence, and remediation recommendations.
5. Export severity-based reports (Markdown/JSON; coming next).

## Requirements

- Python 3.10+
- Git
- Google Gemini API key for the upcoming AI analysis feature

## Setup (Windows / PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
```

## Stage 1: inspect an authorized local source folder

Run from this repository's root:

```powershell
.\.venv\Scripts\python.exe -m reviewer inspect --path "..\CDF-CyberSec-Hackathon-main\vulnerable-app" --manifest ".\reports\source-manifest.json"
```

Or inspect an archive:

```powershell
.\.venv\Scripts\python.exe -m reviewer inspect --path "..\CDF-CyberSec-Hackathon-main.zip"
```

**The inspect command DOES NOT scan for vulnerabilities yet.** It lists candidate
source files and reports skipped entries. The next feature is the Gemini-powered
`scan` command.

## Handling untrusted repositories

Source files are opened as text, not executed. ZIP files are read member by member
without extracting to disk. Unsafe ZIP members, symlinks, suspicious hidden files,
common dependency folders, and oversized files are skipped. Supported text formats
use UTF-8. Avoid running any uploaded code. Do not analyze or upload client code,
production credentials, or confidential files to third-party AI services.

These rules are a starting point, not a comprehensive data-loss-prevention solution.
Review allowed content before enabling outbound Gemini calls.

## Organizer materials

The challenge instructions and CDF TaskFlow app are supplied in the organizer's
`CDF-CyberSec-Hackathon-main.zip` archive. Keep the extracted organizer project in
an adjacent folder for local testing. Do not present organizer code as original work.

## Attribution

- Hackathon task and synthetic CDF TaskFlow source: CDF organizers.
- Planned model integration: Google Gemini API, subject to model access and terms.
- Python libraries listed in `requirements.txt`.

## Status and next step

**Implemented:** source folder/ZIP intake, file manifest, limits, filtering, tests.

**Not yet implemented:** AI findings, fixes, severity assignment, evidence validation,
security assessment report, demo video.
