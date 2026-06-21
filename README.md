# 403 Bypass — Professional Recon & Response Analysis

An accuracy-first utility for security professionals to analyze HTTP 403 responses, reduce false positives, and identify legitimate access-control bypasses using advanced request techniques and response fingerprinting.

This repository contains the scanner [403_bypass_v3.py](403-bypass.py) and payload lists used for testing.

Author: Nithin

---

## Key Capabilities

- UI: interactive console with colorized output (Colorama) and a modern ASCII banner.
- Input modes: single `-u/--url` or multi-target `-l/--list` (file of URLs).
- Request engine: `requests.Session()` with connection pooling, `HTTPAdapter` retries (exponential backoff), `ThreadPoolExecutor` for concurrent tests, user-agent rotation, per-request timeout, and `--no-verify` SSL toggle.
- Payloads: customizable URL and header payload lists (`403_url_payloads.txt`, `403_header_payloads.txt`).
- Fingerprinting: records status code, HTML `<title>`, content length, SHA256 body hash, and redirect chain.
- Similarity analysis: `difflib.SequenceMatcher()` to compare candidate responses against the baseline 403, reducing false positives.
- Classifications: results are labeled as `NO CHANGE`, `POSSIBLE DIFFERENCE`, `HIGH CONFIDENCE`, `WAF BLOCK`, or `FALSE POSITIVE`.
- WAF detection: simple heuristics for Cloudflare, Akamai, Imperva, Sucuri, F5, ModSecurity (body + header signatures).
- Outputs: human-friendly `results.txt` and line-delimited JSON `results.json` for programmatic consumption.
- Reporting: rich CLI tables via `rich` and progress indicators via `tqdm`.

---

## Installation

1. Create a virtual environment (recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

---

## Quick Start

- Interactive mode:

```bash
python3 403_bypass_v3.py
```

- Single URL:

```bash
python3 403_bypass_v3.py -u https://example.com/secret/
```

- Multiple targets from a file:

```bash
python3 403_bypass_v3.py -l urls.txt
```

- Common flags:

- `-p/--payloads` : path to URL payload file (default: 403_url_payloads.txt)
- `--headers-file` : path to header payload file (default: 403_header_payloads.txt)
- `-o/--output` : human-readable output file (default: results.txt)
- `--no-verify` : disable SSL cert verification
- `--combine` : test URL payload + header payload combinations (slower)
- `-t/--threads` : number of worker threads
- `--timeout` : request timeout in seconds

Example with options:

```bash
python3 403_bypass_v3.py -u https://example.com -t 20 --timeout 7 --combine -o results.txt
```

---

## Output Formats

- `results.txt` — human-readable append log of confirmed bypasses (URL, payload, header, status, length, title).
- `results.json` — line-delimited JSON objects, example record:

```json
{
	"url": "https://example.com/admin",
	"status": 200,
	"title": "Admin — Example",
	"length": 2345,
	"similarity": 0.1234,
	"classification": "HIGH CONFIDENCE"
}
```

---

## Statistics & Reporting

At the end of a run the scanner prints a summary table that includes:

- Total requests sent
- Bypasses found
- WAF blocks detected
- False positives filtered
- Possible differences (low-confidence changes)
- Redirects observed
- Errors

The tool also prints a compact Rich table of findings for quick review.

---

## Customization

- Extend or replace payloads by editing [403_url_payloads.txt](403_url_payloads.txt) and [403_header_payloads.txt](403_header_payloads.txt).
- Adjust similarity threshold in the script (`SIMILARITY_THRESHOLD`) if you need stricter or looser matching.

---

## Responsible Use

This tool is intended for authorized security testing only. You must have explicit written permission to test any target. The author and contributors are not responsible for misuse.

---

If you'd like, I can also add example `urls.txt`, CI checks, or a short demo script that runs a non-destructive scan against a local test server.
