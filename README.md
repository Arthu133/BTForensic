# BTForensic

BTForensic is a defensive, read-only command-line tool for SOC and DFIR analysis of copied Chromium-based browser `User Data` folders, including Google Chrome, Microsoft Edge, Chromium, and Brave.

The primary use case is Windows incident response: collect a user's browser folder, such as `C:\Users\username\AppData\Local\Google\Chrome\User Data` or `C:\Users\username\AppData\Local\Microsoft\Edge\User Data`, then run BTForensic against that copied folder from a terminal. Original browser files are never modified: SQLite databases are copied to a temporary directory before being opened in read-only mode.

## Safety Model

- Runs locally and analyzes local or copied browser artifacts only.
- Does not modify original browser files.
- Copies Chromium SQLite databases before reading them. Files such as `History` and `Network\Cookies` are SQLite databases even though they do not use a `.db` extension.
- Does not print or export raw cookie values.
- Cookie output includes metadata and `value_sha256` only. Encrypted cookie bytes from `encrypted_value` are hashed when a plaintext value is unavailable.
- Sensitive headers such as `Cookie`, `Authorization`, `Set-Cookie`, and token-like headers are redacted.
- Sensitive query parameters such as `token`, `session`, `auth`, `key`, `password`, and `code` are masked.
- Missing artifacts are logged as warnings and do not stop the analysis.

## Installation

### Install from a Git repository

Anyone can install it directly from GitHub:

```powershell
git clone https://github.com/Arthu133/BTForensic.git
cd BTForensic
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
BTForensic --version
```

Users can also install directly from GitHub without keeping a local clone:

```powershell
pip install git+https://github.com/Arthu133/BTForensic.git
BTForensic --help
```

### Local development install

```powershell
cd BTForensic
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

### Future PyPI install

If the package is published to PyPI later, installation becomes:

```bash
pip install BTForensic
BTForensic --help
```

BTForensic uses only Python standard library modules. The external `jq` command is optional. When `jq` is installed, it is used to normalize JSON files such as `Bookmarks`; otherwise BTForensic logs a warning and uses a Python fallback.

Optional:

```powershell
winget install jqlang.jq
```

## Usage

When an analysis starts, the terminal displays a `BTForensic` banner before the logs:

```text
 ____ _____ _____                          _
| __ )_   _|  ___|__  _ __ ___ _ __  ___(_) ___
|  _ \ | | | |_ / _ \| '__/ _ \ '_ \/ __| |/ __|
| |_) || | |  _| (_) | | |  __/ | | \__ \ | (__
|____/ |_| |_|  \___/|_|  \___|_| |_|___/_|\___|

Defensive Chromium browser forensics | read-only local analysis
```

Chrome on Windows:

```powershell
BTForensic --user-data "C:\Users\username\AppData\Local\Google\Chrome\User Data" --target "example.com" --output ".\case_example"
```

Microsoft Edge on Windows:

```powershell
BTForensic --user-data "C:\Users\username\AppData\Local\Microsoft\Edge\User Data" --target "example.com" --output ".\case_edge"
```

Analyze a specific profile, such as `Default`:

```powershell
BTForensic --user-data "C:\Users\username\AppData\Local\Google\Chrome\User Data" --profile "Default" --target "https://example.com/login" --output ".\case_login"
```

Use a wider correlation window:

```powershell
BTForensic --user-data "C:\Cases\user01\Chrome\User Data" --target "example.com" --output ".\case_user01" --window-minutes 60 --verbose
```

## Parameters

- `--user-data`: required path to the collected Chromium browser `User Data` directory.
- `--target`: required domain or URL to investigate.
- `--output`: required report output directory.
- `--profile`: optional profile name, such as `Default`, `Profile 1`, or `Profile 2`.
- `--window-minutes`: optional time window for correlating related visits and downloads. Default: `30`.
- `--verbose`: enables detailed logs.

## Output Structure

```text
case_example/
  BTForensic_report.md
  timeline.json
  artifacts/
    history_matches.json
    visits_matches.json
    cookies_matches.json
    bookmarks_matches.json
    downloads_matches.json
    network_log_matches.json
    origins_and_referrers.json
  raw_converted/
    history_urls.json
    history_visits.json
    cookies.json
    bookmarks.json
  logs/
    BTForensic.log
```

## Analyzed Artifacts

- `History`: `urls`, `visits`, visit times, titles, transitions, typed count, visit count, and nearby related URLs.
- `Cookies` or `Network/Cookies`: target-domain cookies and third-party cookies associated with related time-window domains, without raw values.
- `Bookmarks`: JSON bookmarks matching the target domain or URL.
- `Downloads`: `downloads` and `downloads_url_chains` entries related to the target or within the target visit window.
- Network text artifacts: `.tmp`, `.log`, `.json`, `.ldb`, `.txt`, and `.dat` files under profile, `Network`, `Network Logs`, `Service Worker`, and `Cache`.
- Origins/referrers/initiators: direct target calls, callers of the target, third-party domains in the time window, possible redirects.

## Tests

```powershell
python -m unittest discover -s tests
```

## Publishing For Public Use

Create a GitHub repository named `BTForensic`, then run these commands inside the project directory:

```powershell
git init
git add .
git commit -m "Initial BTForensic release"
git branch -M main
git remote add origin https://github.com/Arthu133/BTForensic.git
git push -u origin main
```

After that, anyone can download and install the tool with:

```powershell
git clone https://github.com/Arthu133/BTForensic.git
cd BTForensic
pip install -e .
```

## Notes

Chrome/WebKit timestamps are converted from microseconds since `1601-01-01T00:00:00Z` to ISO 8601 UTC and local time where applicable.

Target matching accepts domains and URLs. A target like `example.com` matches `example.com`, `www.example.com`, `sub.example.com`, and URLs under those hosts. A full URL target prioritizes that path while still grouping related evidence by domain.

On Chromium-based browsers, files such as `Default\History` and `Default\Network\Cookies` are SQLite databases without a `.db` extension. BTForensic reads those normal browser filenames directly and does not rename or modify them.
