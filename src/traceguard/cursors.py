"""Opaque process-local cursors bound to immutable search inputs and file state."""

from __future__ import annotations

import secrets
from collections import OrderedDict
from dataclasses import dataclass

from traceguard.access import FileSnapshot
from traceguard.errors import CursorError


@dataclass(frozen=True)
class CursorState:
    sources: tuple[FileSnapshot, ...]
    query_fingerprint: str
    source_index: int
    byte_offset: int
    line_number: int


class CursorStore:
    """Keep cursor payloads server-side so clients cannot edit offsets or paths."""

    def __init__(self, *, capacity: int = 256) -> None:
        self._capacity = capacity
        self._states: OrderedDict[str, CursorState] = OrderedDict()

    def issue(self, state: CursorState) -> str:
        token = secrets.token_urlsafe(32)
        self._states[token] = state
        self._states.move_to_end(token)
        while len(self._states) > self._capacity:
            self._states.popitem(last=False)
        return token

    def resolve(
        self,
        token: str,
        *,
        sources: tuple[FileSnapshot, ...],
        query_fingerprint: str,
    ) -> CursorState:
        if not isinstance(token, str) or len(token) > 128:
            raise CursorError("invalid_cursor", "The pagination cursor is invalid or expired.")
        state = self._states.get(token)
        if state is None:
            raise CursorError(
                "invalid_cursor",
                "The pagination cursor is invalid or expired; restart the search.",
            )
        if tuple(source.identity() for source in state.sources) != tuple(
            source.identity() for source in sources
        ):
            raise CursorError(
                "source_mismatch",
                "The cursor belongs to a different source-file set; restart the search.",
            )
        if state.query_fingerprint != query_fingerprint:
            raise CursorError(
                "query_mismatch",
                "The cursor belongs to a different search; restart the search.",
            )
        self._states.move_to_end(token)
        return state
