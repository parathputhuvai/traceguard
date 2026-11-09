"""Safe rendering helpers for untrusted log evidence."""

from __future__ import annotations

import codecs
import hashlib
from collections.abc import Iterator


_ANSI_MARKER = "[ANSI escape]"
_TRUNCATED_MARKER = "[truncated]"
_ESCAPE = "\x1b"


class _DecodedCharacters:
    def __init__(self, raw: bytes) -> None:
        self._characters = iter(_decoded_characters(raw))
        self._buffer: list[str] = []
        self._start = 0
        self._finished = False

    def peek(self, offset: int = 0) -> str | None:
        while self._start + offset >= len(self._buffer) and not self._finished:
            try:
                self._buffer.append(next(self._characters))
            except StopIteration:
                self._finished = True
        index = self._start + offset
        return self._buffer[index] if index < len(self._buffer) else None

    def consume(self, count: int = 1) -> None:
        self._start += count
        if self._start >= 512 and self._start * 2 >= len(self._buffer):
            del self._buffer[: self._start]
            self._start = 0


def sanitize_evidence(raw: bytes, *, max_characters: int = 1024) -> dict[str, object]:
    budget = max(0, max_characters)
    digest = hashlib.sha256(raw).hexdigest()
    characters = _DecodedCharacters(raw)
    output: list[str] = []
    output_length = 0
    truncated = False

    def emit(value: str) -> bool:
        nonlocal output_length, truncated
        if output_length + len(value) > budget:
            truncated = True
            return False
        output.append(value)
        output_length += len(value)
        return True

    while (character := characters.peek()) is not None:
        if character == _ESCAPE:
            following = characters.peek(1)
            if following == "[":
                sequence_length = _csi_length(characters, budget)
                if sequence_length is not None:
                    if not emit(_ANSI_MARKER):
                        break
                    characters.consume(sequence_length)
                    continue
            elif following == "]":
                sequence_length = _osc_length(characters)
                if sequence_length is not None:
                    if not emit(_ANSI_MARKER):
                        break
                    characters.consume(sequence_length)
                    continue
            if not emit("\\x1b"):
                break
            characters.consume()
            continue

        codepoint = ord(character)
        rendered = (
            f"\\x{codepoint:02x}"
            if codepoint < 32 or codepoint == 127
            else character
        )
        if not emit(rendered):
            break
        characters.consume()

    if not truncated and characters.peek() is not None:
        truncated = True
    if truncated:
        output.append(_TRUNCATED_MARKER)

    return {
        "content": "".join(output),
        "content_sha256": digest,
        "sanitized": True,
        "truncated": truncated,
        "trust": "untrusted_log_content",
    }


def _decoded_characters(raw: bytes) -> Iterator[str]:
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    pending_newline_start: int | None = None
    pending_newline_end = 0

    def flush_newlines() -> Iterator[str]:
        if pending_newline_start is not None:
            for byte_offset in range(pending_newline_start, pending_newline_end):
                yield chr(raw[byte_offset])

    for byte_offset, byte in enumerate(raw):
        decoded = decoder.decode(bytes((byte,)), final=False)
        for character in decoded:
            if character in "\r\n":
                if pending_newline_start is None:
                    pending_newline_start = byte_offset
                pending_newline_end = byte_offset + 1
                continue
            yield from flush_newlines()
            pending_newline_start = None
            pending_newline_end = 0
            yield character

    decoded = decoder.decode(b"", final=True)
    for character in decoded:
        if character in "\r\n":
            if pending_newline_start is None:
                pending_newline_start = len(raw)
            pending_newline_end = len(raw)
            continue
        yield from flush_newlines()
        pending_newline_start = None
        pending_newline_end = 0
        yield character


def _csi_length(characters: _DecodedCharacters, budget: int) -> int | None:
    limit = max(3, budget)
    index = 2
    while index < limit:
        character = characters.peek(index)
        if character is None or not "\x30" <= character <= "\x3f":
            break
        index += 1
    while index < limit:
        character = characters.peek(index)
        if character is None or not "\x20" <= character <= "\x2f":
            break
        index += 1
    if index < limit:
        character = characters.peek(index)
        if character is not None and "\x40" <= character <= "\x7e":
            return index + 1
    return None


def _osc_length(characters: _DecodedCharacters) -> int | None:
    for index in range(2, 258):
        character = characters.peek(index)
        if character is None:
            return None
        if character == "\x07":
            return index + 1
        if character == _ESCAPE and index + 1 < 258:
            following = characters.peek(index + 1)
            if following == "\\":
                return index + 2
    return None
