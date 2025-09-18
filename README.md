# DogSubDomains finder — Subdomain Recon & HTTP Validation

**Short description**
Ðogspløit.py is an interactive Python tool that aggregates subdomains using multiple collectors, deduplicates results, and validates reachable hosts via `httpx`. It is intended for authorized security testing and reconnaissance only.

## Features
- Runs collectors if available: `subfinder`, `findomain`, `assetfinder`, `amass`
- Merges and deduplicates results into a single list
- Validates HTTP endpoints (status codes 200, 302, 403, 401) using `httpx` or `httpx-toolkit`
- Interactive prompts: domain input, verbose mode, optional save location, and cleanup of temporary files
- Minimal dependencies and clear feedback when tools are missing

## Requirements
- Python 3.8+
- Optional tools (recommended and must be in PATH):
  - `subfinder`
  - `findomain`
  - `assetfinder`
  - `amass`
  - `httpx` **or** `httpx-toolkit`
- Network access for the target domain (authorized testing only)

## Quick start
1. Place `dogsploit.py` in your working directory.
2. Run:
```bash
python3 dogsploit.py
