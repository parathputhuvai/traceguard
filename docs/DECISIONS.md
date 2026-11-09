- Dev environment: Windows 11 + VS Code, no WSL/Kali.
- No local testing and no real LLM host testing. Code must import cleanly on
  Windows (no top-level pwd/grp/fcntl imports; guard os.geteuid).
- Skip phases 6-7. Phase 8 README must state "not tested on Linux; no
  evaluation results" under Known Limitations.
- Optional: GitHub Actions CI on ubuntu-latest.

## Approved implementation decisions

- Implement the initial MCP server and processing layers after architecture
  approval; do not implement LLM-host integration or Phase 6-7 evaluations.
- Use the maintained Python MCP SDK's FastMCP API over stdio and the third-party
  `regex` package for untrusted dynamic patterns.
- Restrict explicit file paths to configured approved roots. Default to
  `/var/log`; use `TRACEGUARD_ALLOWED_ROOTS` for custom locations. Reject
  symbolic-link file paths and keep all processing read-only.
- Provide metadata, dynamic search, and bounded context tools. Use in-memory,
  process-local random cursors bound to file snapshots and the search query;
  restarting the server invalidates cursors.
- Develop on Windows without claiming Linux, MCP Inspector, real-host, or
  performance validation. The README must include the exact Known Limitations
  statement: "not tested on Linux; no evaluation results".
- Appends are tolerated when file identity matches, size has not decreased, and
  the initial head fingerprint is unchanged.
- Evidence sanitization uses a linear scanner with a bounded 256-character OSC
  terminator lookahead.
- Regex matching uses a 2.0-second per-match timeout; timed-out lines are skipped
  and reported, and a scan stops after three regex timeouts.