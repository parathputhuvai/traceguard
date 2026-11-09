"""Public, safe-to-return errors used by TraceGuard operations."""


class TraceGuardError(Exception):
    """An expected input, access, or processing error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class LogAccessError(TraceGuardError):
    """A supplied log file cannot be safely accessed."""


class CursorError(TraceGuardError):
    """A cursor is invalid, expired, or no longer matches its sources."""

