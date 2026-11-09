"""Explicit-path validation and read-only access to approved log files."""

from __future__ import annotations

import hashlib
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Generator, Sequence

from traceguard.errors import LogAccessError


@dataclass(frozen=True)
class FileSnapshot:
    path: str
    device: int
    inode: int
    size: int
    mtime_ns: int
    head_length: int = 0
    head_sha256: str = ""

    @classmethod
    def from_stat(cls, path: Path, file_stat: os.stat_result) -> FileSnapshot:
        return cls(
            path=str(path),
            device=file_stat.st_dev,
            inode=file_stat.st_ino,
            size=file_stat.st_size,
            mtime_ns=file_stat.st_mtime_ns,
        )

    def identity(self) -> tuple[str, int, int]:
        return (self.path, self.device, self.inode)

    def to_dict(self) -> dict[str, int | str]:
        return {
            "path": self.path,
            "device": self.device,
            "inode": self.inode,
            "size_bytes": self.size,
            "modified_ns": self.mtime_ns,
        }

    def matches(self, file_stat: os.stat_result) -> bool:
        return (
            self.device == file_stat.st_dev
            and self.inode == file_stat.st_ino
        )


class FileAccess:
    """Restrict reads to configured roots and explicitly supplied regular files."""

    def __init__(self, allowed_roots: Sequence[str | Path]) -> None:
        if not allowed_roots:
            raise ValueError("At least one approved root is required.")
        self._roots = tuple(Path(root).expanduser().resolve() for root in allowed_roots)

    @classmethod
    def from_environment(cls) -> FileAccess:
        configured = os.environ.get("TRACEGUARD_ALLOWED_ROOTS")
        roots = (
            [Path(part).expanduser() for part in configured.split(os.pathsep) if part]
            if configured
            else [Path("/var/log")]
        )
        return cls(roots)

    def validate_paths(self, paths: Sequence[str]) -> tuple[FileSnapshot, ...]:
        if not isinstance(paths, (list, tuple)) or not paths:
            raise LogAccessError("invalid_paths", "Provide at least one explicit log file path.")
        if len(paths) > 20:
            raise LogAccessError("too_many_paths", "A request may include at most 20 log files.")

        snapshots: list[FileSnapshot] = []
        seen: set[str] = set()
        for supplied_path in paths:
            if not isinstance(supplied_path, str) or not supplied_path.strip():
                raise LogAccessError("invalid_path", "Every log path must be a non-empty string.")
            if len(supplied_path) > 4096:
                raise LogAccessError("invalid_path", "A log path exceeds the 4096-character limit.")
            if Path(supplied_path).suffix.lower() == ".gz":
                raise LogAccessError(
                    "compressed_not_supported",
                    "Compressed rotated logs are not supported; supply a plain-text log file.",
                )
            snapshot = self.snapshot(supplied_path)
            if snapshot.path in seen:
                raise LogAccessError("duplicate_path", "Duplicate log paths are not allowed.")
            seen.add(snapshot.path)
            snapshots.append(snapshot)
        return tuple(snapshots)

    def snapshot(self, supplied_path: str) -> FileSnapshot:
        candidate = Path(supplied_path).expanduser()
        try:
            if candidate.is_symlink():
                raise LogAccessError("symlink_not_allowed", "Symbolic-link log paths are not allowed.")
            resolved = candidate.resolve(strict=True)
            self._ensure_approved(resolved)
            file_stat = resolved.stat()
        except LogAccessError:
            raise
        except (OSError, RuntimeError, ValueError):
            raise LogAccessError(
                "file_unavailable",
                "The supplied path does not identify an accessible approved file.",
            ) from None

        if not stat.S_ISREG(file_stat.st_mode):
            raise LogAccessError("not_regular_file", "The supplied path must be a regular file.")
        head_length = min(file_stat.st_size, 1024)
        head_sha256 = self._read_head_sha256(
            resolved, file_stat.st_dev, file_stat.st_ino, head_length
        )
        return FileSnapshot(
            path=str(resolved),
            device=file_stat.st_dev,
            inode=file_stat.st_ino,
            size=file_stat.st_size,
            mtime_ns=file_stat.st_mtime_ns,
            head_length=head_length,
            head_sha256=head_sha256,
        )

    @contextmanager
    def open_log(
        self, snapshot: FileSnapshot, *, expected: FileSnapshot | None = None
    ) -> Generator[BinaryIO, None, None]:
        resolved = Path(snapshot.path)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            if resolved.is_symlink() or resolved.resolve(strict=True) != resolved:
                raise LogAccessError("file_changed", "The log file changed.")
            self._ensure_approved(resolved)
            descriptor = os.open(resolved, flags)
            opened_stat = os.fstat(descriptor)
            if not stat.S_ISREG(opened_stat.st_mode):
                raise LogAccessError("not_regular_file", "The supplied path must be a regular file.")
            required = expected or snapshot
            if (
                required.identity() != snapshot.identity()
                or opened_stat.st_dev != required.device
                or opened_stat.st_ino != required.inode
                or opened_stat.st_size < required.size
                or self._descriptor_head_sha256(descriptor, required.head_length)
                != required.head_sha256
            ):
                raise LogAccessError(
                    "file_changed",
                    "The log file changed since it was inspected; restart the investigation.",
                )
            stream = os.fdopen(descriptor, "rb")
            descriptor = None
        except LogAccessError:
            raise
        except (OSError, RuntimeError, ValueError):
            if expected is not None:
                raise LogAccessError(
                    "file_changed",
                    "The log file changed since it was inspected; restart the investigation.",
                ) from None
            raise LogAccessError(
                "file_unavailable",
                "The supplied path cannot be opened for reading.",
            ) from None
        finally:
            if descriptor is not None:
                os.close(descriptor)

        try:
            yield stream
        finally:
            try:
                try:
                    opened_stat = os.fstat(stream.fileno())
                    changed = (
                        opened_stat.st_size < snapshot.size
                        or self._descriptor_head_sha256(
                            stream.fileno(), snapshot.head_length
                        )
                        != snapshot.head_sha256
                    )
                except OSError:
                    raise LogAccessError(
                        "file_changed",
                        "The log file changed while it was being processed; restart the investigation.",
                    ) from None
                if changed:
                    raise LogAccessError(
                        "file_changed",
                        "The log file changed while it was being processed; restart the investigation.",
                    )
            finally:
                stream.close()

    def verify_continuity(self, old_snapshot: FileSnapshot) -> FileSnapshot:
        try:
            current = self.snapshot(old_snapshot.path)
            if (
                current.identity() != old_snapshot.identity()
                or current.size < old_snapshot.size
            ):
                raise LogAccessError("file_changed", "The log file changed.")
            old_head_sha256 = self._read_head_sha256(
                Path(current.path),
                current.device,
                current.inode,
                old_snapshot.head_length,
            )
            if old_head_sha256 != old_snapshot.head_sha256:
                raise LogAccessError("file_changed", "The log file changed.")
        except LogAccessError:
            raise LogAccessError(
                "file_changed",
                "A log file changed since the cursor was issued; restart the investigation.",
            ) from None
        return current

    def verify_snapshot(self, snapshot: FileSnapshot) -> None:
        self.verify_continuity(snapshot)

    @staticmethod
    def _descriptor_head_sha256(descriptor: int, length: int) -> str:
        original_offset: int | None = None
        try:
            original_offset = os.lseek(descriptor, 0, os.SEEK_CUR)
            os.lseek(descriptor, 0, os.SEEK_SET)
            remaining = length
            digest = hashlib.sha256()
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    raise LogAccessError("file_changed", "The log file changed.")
                digest.update(chunk)
                remaining -= len(chunk)
            return digest.hexdigest()
        except LogAccessError:
            raise
        except OSError:
            raise LogAccessError("file_changed", "The log file changed.") from None
        finally:
            if original_offset is not None:
                try:
                    os.lseek(descriptor, original_offset, os.SEEK_SET)
                except OSError:
                    raise LogAccessError("file_changed", "The log file changed.") from None

    @classmethod
    def _read_head_sha256(
        cls, path: Path, device: int, inode: int, length: int
    ) -> str:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            if path.is_symlink() or path.resolve(strict=True) != path:
                raise LogAccessError("file_changed", "The log file changed.")
            descriptor = os.open(path, flags)
            file_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_dev != device
                or file_stat.st_ino != inode
                or file_stat.st_size < length
            ):
                raise LogAccessError("file_changed", "The log file changed.")
            return cls._descriptor_head_sha256(descriptor, length)
        except LogAccessError:
            raise
        except (OSError, RuntimeError, ValueError):
            raise LogAccessError(
                "file_unavailable",
                "The supplied path cannot be opened for reading.",
            ) from None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _ensure_approved(self, path: Path) -> None:
        if not any(path == root or root in path.parents for root in self._roots):
            raise LogAccessError(
                "path_not_approved",
                "The supplied path is outside the configured approved log roots.",
            )
