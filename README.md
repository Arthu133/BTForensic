# BTForensic

BTForensic is a defensive, read-only Linux command-line tool for local forensic analysis of Chromium-based browser artifacts, including Google Chrome, Chromium, Brave, and Microsoft Edge.

It receives a browser `User Data` directory and a target domain or URL, then produces structured JSON artifacts, a consolidated timeline, logs, and a Markdown report. Original browser files are never modified: SQLite databases are copied to a temporary directory before being opened in read-only mode.

## Safety Model

- Runs locally and analyzes local browser artifacts only.
- Does not modify original browser files.
- Copies SQLite databases before reading them.
- Does not print or export raw cookie values.
- Cookie output includes metadata and `value_sha256` only.
- Sensitive headers such as `Cookie`, `Authorization`, `Set-Cookie`, and token-like headers are redacted.
- Sensitive query parameters such as `token`, `session`, `auth`, `key`, `password`, and `code` are masked.
- Missing artifacts are logged as warnings and do not stop the analysis.

## Installation

### Install from a Git repository

After publishing this project to GitHub, anyone can install it directly from the terminal:

```bash
git clone https://github.com/Arthu133/BTForensic.git
cd BTForensic
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
BTForensic --version
```

Users can also install directly from GitHub without keeping a local clone:

```bash
pip install git+https://github.com/Arthu133/BTForensic.git
BTForensic --help
```

### Local development install

```bash
cd BTForensic
python3 -m venv .venv
source .venv/bin/activate
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

```bash
sudo apt-get install jq
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

```bash
BTForensic --user-data "/home/user/.config/google-chrome" --target "example.com" --output "./case_example"
```

Analyze a specific profile:

```bash
BTForensic --user-data "/home/user/.config/google-chrome" --profile "Default" --target "https://example.com/login" --output "./case_login"
```

Use a wider correlation window:

```bash
BTForensic --user-data "/home/user/.config/BraveSoftware/Brave-Browser" --target "example.com" --output "./case_brave" --window-minutes 60 --verbose
```

## Parameters

- `--user-data`: required path to the Chromium browser `User Data` directory.
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

```bash
python -m unittest discover -s tests
```

## Publishing For Public Use

Create a GitHub repository named `BTForensic`, then run these commands inside the project directory:

```bash
git init
git add .
git commit -m "Initial BTForensic release"
git branch -M main
git remote add origin https://github.com/Arthu133/BTForensic.git
git push -u origin main
```

After that, anyone can download and install the tool with:

```bash
git clone https://github.com/Arthu133/BTForensic.git
cd BTForensic
pip install -e .
```

## Notes

Chrome/WebKit timestamps are converted from microseconds since `1601-01-01T00:00:00Z` to ISO 8601 UTC and local time where applicable.

Target matching accepts domains and URLs. A target like `example.com` matches `example.com`, `www.example.com`, `sub.example.com`, and URLs under those hosts. A full URL target prioritizes that path while still grouping related evidence by domain.
