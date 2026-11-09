from __future__ import annotations

from pathlib import Path

import pytest

import traceguard.engine as engine_module
from traceguard.access import FileAccess
from traceguard.cursors import CursorStore
from traceguard.engine import LogEngine
from traceguard.errors import CursorError, LogAccessError


@pytest.fixture
def engine(tmp_path: Path) -> tuple[LogEngine, Path]:
    return LogEngine(FileAccess([tmp_path]), CursorStore()), tmp_path


def test_search_returns_sourced_matches_and_continues(engine: tuple[LogEngine, Path]) -> None:
    log_engine, root = engine
    first = root / "auth.log"
    second = root / "auth.log.1"
    first.write_text("alpha\nFailed password for user1\n", encoding="utf-8")
    second.write_text("Failed password for user2\n", encoding="utf-8")

    result = log_engine.search_logs(
        [str(first), str(second)], "Failed password", use_regex=False, page_size=1
    )
    assert result["summary"]["matching_records"] == 2  # type: ignore[index]
    assert result["pagination"]["has_more"] is True  # type: ignore[index]
    assert result["evidence"][0]["source"] == str(first.resolve())  # type: ignore[index]

    next_page = log_engine.search_logs(
        [str(first), str(second)],
        "Failed password",
        use_regex=False,
        page_size=1,
        cursor=result["pagination"]["next_cursor"],  # type: ignore[index]
    )
    assert next_page["evidence"][0]["source"] == str(second.resolve())  # type: ignore[index]
    assert next_page["pagination"]["has_more"] is False  # type: ignore[index]


def test_cursor_rejects_changed_source(engine: tuple[LogEngine, Path]) -> None:
    log_engine, root = engine
    path = root / "auth.log"
    path.write_text("match one\nmatch two\n", encoding="utf-8")
    result = log_engine.search_logs([str(path)], "match", use_regex=False, page_size=1)
    path.write_text("replacement\n", encoding="utf-8")

    with pytest.raises((CursorError, LogAccessError)):
        log_engine.search_logs(
            [str(path)],
            "match",
            use_regex=False,
            page_size=1,
            cursor=result["pagination"]["next_cursor"],  # type: ignore[index]
        )


def test_access_rejects_paths_outside_approved_root(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    disallowed = tmp_path / "elsewhere"
    allowed.mkdir()
    disallowed.mkdir()
    secret = disallowed / "auth.log"
    secret.write_text("evidence\n", encoding="utf-8")

    with pytest.raises(LogAccessError):
        FileAccess([allowed]).validate_paths([str(secret)])


def test_access_rejects_final_symlink(tmp_path: Path) -> None:
    source = tmp_path / "auth.log"
    link = tmp_path / "linked.log"
    source.write_text("evidence\n", encoding="utf-8")
    try:
        link.symlink_to(source)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable on this system.")

    with pytest.raises(LogAccessError):
        FileAccess([tmp_path]).validate_paths([str(link)])


def test_search_skips_overlong_record_without_matching_fragment(
    engine: tuple[LogEngine, Path],
) -> None:
    log_engine, root = engine
    path = root / "auth.log"
    path.write_bytes(b"needle " + (b"x" * (64 * 1024)) + b"\nneedle\n")

    result = log_engine.search_logs([str(path)], "needle", use_regex=False)
    assert result["summary"]["oversized_lines_skipped"] == 1  # type: ignore[index]
    assert result["summary"]["matching_records"] == 1  # type: ignore[index]


def test_search_can_aggregate_a_dynamic_named_capture(
    engine: tuple[LogEngine, Path],
) -> None:
    log_engine, root = engine
    path = root / "auth.log"
    path.write_text(
        "Failed password for alice\nFailed password for bob\n"
        "Failed password for alice\n",
        encoding="utf-8",
    )

    result = log_engine.search_logs(
        [str(path)],
        r"Failed password for (?P<username>\w+)",
        group_by="username",
    )
    assert result["summary"]["grouping"]["counts"] == {  # type: ignore[index]
        "alice": 2,
        "bob": 1,
    }


def test_appending_between_pages_preserves_cursor_and_reads_new_snapshot(
    engine: tuple[LogEngine, Path],
) -> None:
    log_engine, root = engine
    path = root / "auth.log"
    path.write_text("match one\nmatch two\n", encoding="utf-8")

    first_page = log_engine.search_logs(
        [str(path)], "match", use_regex=False, page_size=1
    )
    with path.open("a", encoding="utf-8") as stream:
        stream.write("match three\n")

    second_page = log_engine.search_logs(
        [str(path)],
        "match",
        use_regex=False,
        page_size=1,
        cursor=first_page["pagination"]["next_cursor"],  # type: ignore[index]
    )
    assert second_page["evidence"][0]["line_number"] == 2  # type: ignore[index]
    third_page = log_engine.search_logs(
        [str(path)],
        "match",
        use_regex=False,
        page_size=1,
        cursor=second_page["pagination"]["next_cursor"],  # type: ignore[index]
    )
    assert third_page["evidence"][0]["line_number"] == 3  # type: ignore[index]


def test_open_log_allows_append_while_open(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_bytes(b"first\n")
    access = FileAccess([tmp_path])
    snapshot = access.validate_paths([str(path)])[0]

    with access.open_log(snapshot) as stream:
        assert stream.read() == b"first\n"
        with path.open("ab") as append_stream:
            append_stream.write(b"second\n")


def test_truncation_breaks_file_continuity(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_bytes(b"original log contents\n")
    access = FileAccess([tmp_path])
    snapshot = access.validate_paths([str(path)])[0]
    path.write_bytes(b"short\n")

    with pytest.raises(LogAccessError) as error:
        access.verify_continuity(snapshot)
    assert error.value.code == "file_changed"


def test_same_file_replacement_with_changed_head_breaks_continuity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "auth.log"
    path.write_bytes(b"original contents\n")
    access = FileAccess([tmp_path])
    snapshot = access.validate_paths([str(path)])[0]
    path.write_bytes(b"replacement contents\n")

    with pytest.raises(LogAccessError) as error:
        access.verify_continuity(snapshot)
    assert error.value.code == "file_changed"


def test_regex_timeout_skips_line_and_continues(
    engine: tuple[LogEngine, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    log_engine, root = engine
    path = root / "auth.log"
    catastrophic_line = "a" * 40 + "!"
    path.write_text(f"{catastrophic_line}\nneedle later\n", encoding="utf-8")
    real_compile = engine_module.regex.compile
    real_pattern = real_compile(r"(?:(a+)+$)|needle")

    class TimeoutOnSlowLine:
        groupindex: dict[str, int] = {}

        def search(self, text: str, *, timeout: float):
            if text.rstrip("\r\n") == catastrophic_line:
                raise TimeoutError
            return real_pattern.search(text, timeout=timeout)

    monkeypatch.setattr(
        engine_module.regex, "compile", lambda _pattern, _flags=0: TimeoutOnSlowLine()
    )
    result = log_engine.search_logs([str(path)], r"(?:(a+)+$)|needle")

    assert result["status"] == "partial"
    assert result["evidence"][0]["line_number"] == 2  # type: ignore[index]
    assert result["summary"]["regex_timeouts"] == 1  # type: ignore[index]
    assert result["summary"]["regex_timeout_lines"] == [  # type: ignore[index]
        {
            "line_number": 1,
            "byte_offset": 0,
            "source": str(path.resolve()),
        }
    ]


def test_three_regex_timeouts_stop_and_cursor_advances(
    engine: tuple[LogEngine, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    log_engine, root = engine
    path = root / "auth.log"
    catastrophic_line = "a" * 40 + "!"
    path.write_text(
        f"{catastrophic_line}\n{catastrophic_line}\n{catastrophic_line}\nneedle later\n",
        encoding="utf-8",
    )
    real_compile = engine_module.regex.compile
    real_pattern = real_compile(r"(?:(a+)+$)|needle")

    class TimeoutOnSlowLines:
        groupindex: dict[str, int] = {}

        def search(self, text: str, *, timeout: float):
            if text.rstrip("\r\n") == catastrophic_line:
                raise TimeoutError
            return real_pattern.search(text, timeout=timeout)

    monkeypatch.setattr(
        engine_module.regex, "compile", lambda _pattern, _flags=0: TimeoutOnSlowLines()
    )
    stopped = log_engine.search_logs([str(path)], r"(?:(a+)+$)|needle")
    assert stopped["status"] == "partial"
    assert stopped["summary"]["regex_timeouts"] == 3  # type: ignore[index]
    assert (
        stopped["summary"]["stopped_reason"] == "regex_timeout_limit"  # type: ignore[index]
    )
    assert "too expensive" in stopped["summary"]["message"]  # type: ignore[index]

    continuation = log_engine.search_logs(
        [str(path)],
        r"(?:(a+)+$)|needle",
        cursor=stopped["pagination"]["next_cursor"],  # type: ignore[index]
    )
    assert continuation["evidence"][0]["line_number"] == 4  # type: ignore[index]
    assert continuation["summary"]["regex_timeouts"] == 0  # type: ignore[index]
