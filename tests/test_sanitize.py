from __future__ import annotations

import hashlib
import time

from traceguard.sanitize import sanitize_evidence


def test_sanitizes_csi_and_bel_terminated_osc() -> None:
    csi = sanitize_evidence(b"before\x1b[31mred\x1b[0mafter")
    assert csi["content"] == "before[ANSI escape]red[ANSI escape]after"

    osc = sanitize_evidence(b"before\x1b]title\x07after")
    assert osc["content"] == "before[ANSI escape]after"

    osc_st = sanitize_evidence(b"before\x1b]title\x1b\\after")
    assert osc_st["content"] == "before[ANSI escape]after"


def test_unterminated_osc_and_lone_escape_are_escaped() -> None:
    unterminated = sanitize_evidence(b"\x1b]unfinished")
    assert unterminated["content"] == r"\x1b]unfinished"

    lone_escape = sanitize_evidence(b"end\x1b")
    assert lone_escape["content"] == r"end\x1b"


def test_truncates_and_hashes_original_bytes() -> None:
    raw = b"abcdef"
    result = sanitize_evidence(raw, max_characters=3)

    assert result["content"] == "abc[truncated]"
    assert result["truncated"] is True
    assert result["content_sha256"] == hashlib.sha256(raw).hexdigest()


def test_repeated_unterminated_osc_prefix_is_bounded() -> None:
    started = time.monotonic()
    result = sanitize_evidence(b"\x1b]" * 32_000)

    assert time.monotonic() - started < 1.0
    assert result["truncated"] is True
    assert result["content_sha256"] == hashlib.sha256(b"\x1b]" * 32_000).hexdigest()
