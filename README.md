# BTForensic

Browser Tool Forensic is a defensive, read-only command-line tool for SOC and DFIR analysis of copied Chromium-based browser `User Data` folders, including Google Chrome, Microsoft Edge, Chromium, and Brave.

The primary use case is Windows incident response: collect a user's browser folder, such as `C:\Users\username\AppData\Local\Google\Chrome\User Data` or `C:\Users\username\AppData\Local\Microsoft\Edge\User Data`, then run BTForensic against that copied folder from a terminal. Original browser files are never modified: SQLite databases are copied to a temporary directory before being opened in read-only mode.

## Safety Model

- Runs locally and analyzes local or copied browser artifacts only.
- Does not modify original browser files.
- Copies Chromium SQLite databases before reading them. Files such as `History` and `Network\Cookies` are SQLite databases even though they do not use a `.db` extension.
- Does not print or export raw cookie values.
- Cookie output includes metadata and `value_sha256` only. Encrypted cookie bytes from `encrypted_value` are hashed when a plaintext value is unavailable.
- Sensitive headers such as `Cookie`, `Authorization`, `Set-Cookie`, and token-like headers are redacted.
- Sensitive query parameters such as `token`, `session`, `auth`, `key`, `password`, and `code` are masked.
- Microsoft Defender for Endpoint correlation is manual and offline: BTForensic generates Advanced Hunting KQL and can parse exported CSV/JSON results, but it never connects to Defender APIs or asks for credentials.
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
made by tzndias
```

Chrome on Windows:

```powershell
BTForensic --user-data "C:\Users\username\AppData\Local\Google\Chrome\User Data" --target "example.com" --output ".\case_example"
```

Terminal-only summary without writing a report:

```powershell
BTForensic --user-data "C:\Users\username\AppData\Local\Google\Chrome\User Data" --target "example.com"
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

Generate Microsoft Defender for Endpoint Advanced Hunting KQL during the browser analysis:

```powershell
BTForensic --user-data "C:\Cases\user01\Edge\User Data" --target "example.com" --output ".\case_user01"
```

The KQL pack will be written to:

```text
.\case_user01\artifacts\defender_hunting_queries.kql
```

After running the primary query in Microsoft Defender for Endpoint Advanced Hunting, export the result as CSV or JSON and feed it back into BTForensic:

```powershell
BTForensic --user-data "C:\Cases\user01\Edge\User Data" --target "example.com" --output ".\case_user01_mde" --defender-input ".\mde_network_results.csv"
```

Write only the Defender KQL pack without creating a full case output:

```powershell
BTForensic --user-data "C:\Cases\user01\Edge\User Data" --target "example.com" --defender-kql-output ".\defender_hunting_queries.kql"
```

## Parameters

- `--user-data`: required path to the collected Chromium browser `User Data` directory.
- `--target`: required domain or URL to investigate.
- `--output`: optional report output directory. If omitted, BTForensic prints the most relevant findings directly in the terminal, including probable caller/origin when available.
- `--profile`: optional profile name, such as `Default`, `Profile 1`, or `Profile 2`.
- `--window-minutes`: optional time window for correlating related visits and downloads. Default: `30`.
- `--defender-input`: optional CSV or JSON exported manually from Microsoft Defender for Endpoint Advanced Hunting.
- `--defender-device`: optional `DeviceName` filter inserted into the generated Defender KQL.
- `--defender-account`: optional account filter inserted into the generated Defender KQL.
- `--defender-kql-output`: optional path to write the Defender KQL pack without a full `--output` folder.
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
    defender_input_summary.json
    defender_hunting_queries.kql
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
- Network `.tmp` artifacts: direct `.tmp` files under the selected profile `Network` directory, such as `User Data\Default\Network\*.tmp`.
- Origins/referrers/initiators: direct target calls, callers of the target, third-party domains in the time window, possible redirects.

## Microsoft Defender For Endpoint Workflow

BTForensic can complement the local browser artifacts with Microsoft Defender for Endpoint telemetry without binding to any API.

The intended workflow is:

1. Run BTForensic against the copied browser `User Data` folder.
2. Open `artifacts\defender_hunting_queries.kql`.
3. In Microsoft Defender XDR Advanced Hunting, run the primary `DeviceNetworkEvents` query.
4. Export the result as CSV or JSON.
5. Rerun BTForensic with `--defender-input` pointing to that export.
6. Review the Defender section in `BTForensic_report.md` and `artifacts\defender_input_summary.json`.

The primary input query focuses on `DeviceNetworkEvents` because it is the most useful Defender table for browser-origin investigation. It can show which endpoint, account, browser process, parent process, command line, remote URL, remote IP, port, protocol, and action type were associated with the target domain or URL.

The generated KQL pack also includes follow-up queries for:

- Browser process tree around the access window using `DeviceProcessEvents`.
- File activity and possible downloads from browser processes using `DeviceFileEvents`.
- Alerts and evidence on devices that contacted the target using `AlertEvidence` and `AlertInfo`.
- Logons on involved devices using `DeviceLogonEvents`.
- Other endpoints that contacted the same target using `DeviceNetworkEvents`.
- Endpoint telemetry around each browser hit using `DeviceEvents`.

No API token, tenant ID, client secret, or Defender credential is used by BTForensic. The operator remains in control of what is copied from Advanced Hunting into the local case folder.

### Recommended Advanced Hunting Input

The best input to import back into BTForensic is the exported result of the first query in `defender_hunting_queries.kql`, named `Primary input query for BTForensic`.

Useful columns include:

- `Timestamp`
- `DeviceName`
- `DeviceId`
- `ActionType`
- `InitiatingProcessAccountName`
- `InitiatingProcessAccountUpn`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `InitiatingProcessParentFileName`
- `InitiatingProcessParentCommandLine`
- `RemoteUrl`
- `RemoteIP`
- `RemotePort`
- `LocalIP`
- `LocalPort`
- `Protocol`

BTForensic summarizes this export into devices, accounts, process names, parent processes, remote URLs, remote IPs, action types, first/last Defender timestamps, and target-matching rows. URL query strings and token-like command-line arguments are masked before being written to BTForensic artifacts.

## Network Origin Investigation Method

For network origin analysis, BTForensic follows the SOC workflow below:

1. Locate the primary `.tmp` file that recorded the access by scanning direct `.tmp` files under the selected profile `Network` directory, equivalent to:

   ```powershell
   Select-String -Path "User Data\Default\Network\*.tmp" -Pattern "URL" -List | % Path
   ```

   Matches from this step are marked as `discovery_method = primary_network_tmp_select_string`. In JSON output, `select_string_equivalent` is written with the real expanded path, for example:

   ```powershell
   Select-String -Path "C:\Users\username\AppData\Local\Microsoft\Edge\User Data\Default\Network\*.tmp" -Pattern "example.com" -List | % Path
   ```
2. When the file is a Chromium network JSON artifact, parse the equivalent of:

   ```jq
   .net.http_server_properties.servers[] | select(.server|test("TARGET"))
   ```

3. From the selected `server` object, extract fields such as `anonymization`, `anonymization_key`, `network_anonymization_key`, or `network_isolation_key`.
4. Decode anonymization payloads with URL decoding, JSON string unescaping, Base64 decoding, and the common Chromium pattern of reading the decoded Base64 bytes from the first `http` byte until trailing null bytes.
5. Report non-target URLs found inside the decoded payload as `inferred_origins_from_anonymization`.

This helps identify the page, top-frame site, frame site, or isolation context that caused the target URL to be called. Sensitive values are still redacted and raw cookie/header secrets are not exported.

## Tests

```powershell
python -m unittest discover -s tests
```

## Notes

Chrome/WebKit timestamps are converted from microseconds since `1601-01-01T00:00:00Z` to ISO 8601 UTC and local time where applicable.

Target matching accepts domains and URLs. A target like `example.com` matches `example.com`, `www.example.com`, `sub.example.com`, and URLs under those hosts. A full URL target prioritizes that path while still grouping related evidence by domain.

On Chromium-based browsers, files such as `Default\History` and `Default\Network\Cookies` are SQLite databases without a `.db` extension. BTForensic reads those normal browser filenames directly and does not rename or modify them.
