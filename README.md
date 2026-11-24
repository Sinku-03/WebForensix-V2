# WebForensix V2 — Cross-Browser Digital Forensic Artifact Analyzer

A Python desktop application for academic browser-forensics triage. It extracts available browser artifacts from Chrome, Microsoft Edge and Firefox profiles, normalizes timestamps to UTC, creates a unified timeline, and generates CSV and HTML reports.

## V2 features

- Dashboard with artifact totals and browser-wise counts.
- Profile discovery for common Windows, macOS and Linux locations.
- Manual selection of a browser profile or evidence folder.
- Chrome / Edge: browsing history, downloads and cookie metadata.
- Firefox: history and cookie metadata; attempts legacy download annotation extraction when present.
- Search-term inference from common search-engine URL query parameters.
- Unified chronological timeline with keyword, browser and artifact-type filters.
- Cross-browser URL matching after removing common tracking parameters.
- Potential duplicate record identification.
- Conservative URL review indicators (heuristics only; not malware verdicts).
- SHA-256 hashes for source SQLite databases.
- Extraction messages / errors visible in the application.
- Professional HTML investigation report and CSV export.
- Cookie values and passwords are not collected.

## Requirements

- Windows 10/11, macOS or Linux.
- Python 3.9+ (tested for syntax with Python 3.14).
- Tkinter.
- No third-party Python packages are required.

## Run on Windows

1. Extract the ZIP.
2. Open the extracted **WebForensix_V2** folder in VS Code (the folder containing `main.py`).
3. Open Terminal → New Terminal.
4. Run:

```powershell
py --version
py main.py
```

If `py` is unavailable, use `python main.py`.

## Run on macOS / Linux

```bash
python3 main.py
```

## How to use

1. Enter a case name and case ID.
2. Click **Scan default browser profiles** to discover standard profiles for the current OS user.
3. Or click **Add profile / evidence folder** and choose a copied profile folder.
4. Watch the status bar for database-level progress.
5. Open the **Dashboard**, **Unified Timeline**, and **Investigation Insights** tabs.
6. Filter the timeline by keyword, browser or artifact type.
7. Export CSV or generate the HTML report.

For a safe UI demonstration, click **Load demo evidence**. Demo records are synthetic and must never be represented as evidence from the computer.

## Windows browser profile paths (common defaults)

- Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default`
- Edge: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`
- Firefox: `%APPDATA%\Mozilla\Firefox\Profiles\<profile>`

Chrome and Edge may have multiple profiles (`Default`, `Profile 1`, `Profile 2`, etc.). The automatic scanner checks common profile folders.

## Forensic handling and limitations

- Prefer verified forensic copies rather than live browser profiles. Close browsers before scanning when possible.
- SQLite backup snapshots are used to obtain a consistent read view where possible. If the browser or another process holds a database lock, the application records an extraction message.
- SHA-256 hashes are calculated for source databases successfully processed. A hash alone does not prove acquisition authenticity or chain of custody.
- Cookie values, authentication tokens and passwords are intentionally not collected.
- Search terms are inferred only from query parameters in visited search-engine URLs.
- Firefox download history varies by Firefox version and may not be available in the profile database. Legacy download annotation extraction is best-effort.
- Browser database schemas change. Missing records do not prove that an activity did not occur.
- URL review indicators are deliberately conservative heuristics (e.g. HTTP, IP-address host, punycode or selected risky keywords). They are not a reputation service, antivirus engine, or proof of maliciousness.
- Cross-browser URL correlation finds normalized URLs appearing in multiple browsers. It does not prove the same person used both browsers or establish intent.
- Duplicate detection is exact-key based and may not identify near-duplicates.
- Validate important findings manually and document acquisition details, examiner, device, time zone, and chain of custody separately.

## Project structure

```text
WebForensix_V2/
├── main.py
├── forensic_core.py
├── report_generator.py
├── README.md
├── requirements.txt
└── data/
    └── .gitkeep
```

## Academic team

**Group name:** WebForensix

- Aryan Keshari
- Priyanshi Keshari
- Vanika Sadana
- Parantap Prakash
- Vivek Sinku

## Project synopsis alignment

Python-based cross-browser artifact extraction and normalization, SQLite browser databases, Chrome/Edge/Firefox, history, downloads, cookies, URLs, timestamps, unified timeline and investigation report.
