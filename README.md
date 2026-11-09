# TraceGuard

TraceGuard is a small, read-only MCP server for investigating explicitly supplied
Linux authentication logs. It processes log data locally with Python and returns
bounded evidence to an MCP-compatible model client. The model—not a fixed rule
catalogue—plans the investigation, chooses searches, and decides what follow-up
evidence is useful.

TraceGuard is for focused investigation, education, and small-scale triage. It is
not an enterprise SIEM replacement or an autonomous detection or remediation
system.

## Architecture

```text
MCP-compatible client
       | stdio MCP
       v
FastMCP tools -> approved-root file access -> streaming search/context engine
                                         -> bounded regex + line sanitization
                                         -> process-local opaque cursors
```

The MCP layer exposes three tools: `get_log_info`, `search_logs`, and
`get_log_context`. The Python engine is independent of the MCP transport.
Dynamic regexes use the third-party `regex` package with a 2.0-second per-match
timeout and an overall operation time limit. Search reads files incrementally; it
does not load an entire log into memory or invoke shell commands.

Log contents are untrusted evidence. TraceGuard escapes terminal control content,
limits returned line length, labels evidence as untrusted, and never modifies
source files. These measures do not prevent all prompt injection. Local Python
processing does not mean the model runs locally: an MCP client may transmit
returned evidence to a cloud model provider.

## Supported sources and access

The initial investigation scope is authentication logs from:

| Linux family | Common authentication log |
| --- | --- |
| Debian-based / Kali | `/var/log/auth.log` |
| RHEL-based | `/var/log/secure` |

Users must pass each file path explicitly. Current plain-text logs and explicitly
supplied uncompressed `.1` rotated logs are supported; compressed logs and
directory discovery are not. Custom files can be used when their containing
directory is configured as an approved root.

The server allows only regular files beneath approved roots. The default root is
`/var/log`; configure additional roots with `TRACEGUARD_ALLOWED_ROOTS`, separated
by the platform's path separator (`:` on Linux/macOS, `;` on Windows). The
requested file itself must not be a symbolic link. Files are opened read-only.
The server never invokes `sudo`, changes permissions, or requires root.

On Debian/Kali, the administrator may grant the intended account access through
the `adm` group when that group has the needed log permissions:

```sh
sudo usermod -aG adm USERNAME
```

Start a new login session after changing group membership. On RHEL-based systems,
do not assume that `adm` exists or grants access. Ask an administrator to
configure least-privilege read access to the intended files (for example, a
dedicated group or ACL that is maintained across log rotation). Do not broaden
permissions on the whole log directory.

The MCP server runs with the permissions of its configured user. A file attached
to a model client is not automatically available to the server.

## Install

Use Python 3.11 or newer. From the project directory:

```sh
python -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1
python -m pip install .
```

To install the test dependency as well:

```sh
python -m pip install ".[dev]"
```

Set approved roots before launching the server. For example, on Linux:

```sh
export TRACEGUARD_ALLOWED_ROOTS="/var/log:/home/USERNAME/security-logs"
python -m traceguard
```

On Windows PowerShell, use semicolons between roots:

```powershell
$env:TRACEGUARD_ALLOWED_ROOTS = "D:\security-logs;D:\test-fixtures"
python -m traceguard
```

The server uses stdio for MCP. Do not write logs or status messages to stdout;
stdio is the protocol channel.

## MCP client configuration

Configure the client to launch the installed Python environment. Replace the
executable and approved roots with paths on the machine that runs the server:

```json
{
  "mcpServers": {
    "traceguard": {
      "command": "/absolute/path/to/traceguard/.venv/bin/python",
      "args": ["-m", "traceguard"],
      "env": {
        "TRACEGUARD_ALLOWED_ROOTS": "/var/log:/home/USERNAME/security-logs"
      }
    }
  }
}
```

The client must support MCP stdio servers. A normal browser conversation cannot
connect to a local stdio process unless its host explicitly supports that
integration.

## Tools

### `get_log_info(path)`

Validates one explicit approved path and returns file identity, size, and
modification metadata. It does not parse the log or infer its format/timestamps.

### `search_logs(paths, pattern, use_regex=true, case_sensitive=false, page_size=20, cursor=null)`

Searches one to twenty explicit files in caller-supplied order. Regex patterns are
limited to 500 characters; page size is 1-50. Set `use_regex=false` for literal
matching. Optionally set `group_by` to a named capture group in the regex to return
bounded counts for the captured values. A returned cursor continues the same query
and ordered source identities. Appends are allowed; truncation, replacement, or a
change to the file's initial head invalidates continuity. Cursors are random,
process-local handles; server restart invalidates them. Responses report
examined/matching records, skipped long lines and regex-timeout lines, completeness,
source identity, and sanitized evidence.

Each regex match has a 2.0-second timeout; an operation has a 10-second processing
deadline. A line that times out is skipped and reported; after three timeouts the
scan stops as partial and recommends simplifying the pattern. These are safeguards,
not performance guarantees. Lines over 64 KiB are skipped rather than partially
searched. Evidence is capped, and the response body is kept below 90,000 bytes to
leave room for MCP framing.

### `get_log_context(path, line_number, before=5, after=5)`

Returns bounded physical-line context around a one-based line number. Each
context bound is 0-20. It does not infer temporal proximity from timestamps.

## Example investigation

1. Ask the model to investigate a specific concern and provide the explicit log
   path (for example `/var/log/auth.log`).
2. The model can call `get_log_info` to verify access.
3. It can select a focused search, such as a literal search for
   `Failed password`, using `search_logs`.
4. It should inspect source paths, line numbers, timestamps as they appear in the
   original text, completeness indicators, and uncertainties. It can refine the
   query or use `get_log_context` for surrounding records.
5. Its report should distinguish observed facts from hypotheses and conclusions;
   a match alone does not establish malicious activity.

Traditional syslog timestamps may omit the year and timezone. TraceGuard preserves
raw log text and does not invent timestamp values or make time-range claims.

## Security and limits

- Read-only processing only; no shell, arbitrary code execution, sudo, automatic
  remediation, or external reputation service.
- Paths must be under configured approved roots; final-component symlinks are
  rejected. Appends to the same file are tolerated when size does not decrease and
  the initial 1 KiB (or smaller original file) fingerprint remains unchanged.
- Regex length, per-match timeout, the three-timeout stop limit, operation time,
  line size, evidence size, and response size are bounded. ANSI CSI/OSC sequences
  are removed by a linear scanner; OSC terminator lookahead is limited to 256
  characters.
- Invalid, expired, or mismatched cursors fail explicitly. A changed, replaced,
  truncated, or head-modified source requires a new search; appends do not.
- Log evidence is untrusted. Sanitization reduces terminal-control risks but
  cannot guarantee resistance to prompt injection.
- Returned evidence may be transmitted by the connected model client. TraceGuard
  does not guarantee that data stays on the server machine.
- No automatic timestamp parsing, cross-source correlation, remote collection,
  compressed rotated-log support, database/history, fixed attack thresholds, or
  attack verdicts are provided.

## Testing status

Focused pytest tests are included under `tests/`. The project has not been
evaluated with MCP Inspector or a real LLM host.

## Known Limitations

- not tested on Linux; no evaluation results
- No Linux permission, rotation, or MCP Inspector behavior has been verified.
- No performance, million-line, token-efficiency, false-positive, or
  investigation-quality measurements are available.
- The default allowed root is `/var/log`; custom roots must be configured
  explicitly.
- Cursors exist only for the lifetime of the running server process.
- Phase 6 and Phase 7 work (LLM-host integration and evaluation/benchmarking) is
  intentionally deferred.
