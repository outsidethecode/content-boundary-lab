"""Injectable time source and exact conversion between datetimes and epoch microseconds (stdlib only)."""

from datetime import datetime, timedelta, timezone
from typing import Protocol, runtime_checkable

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ONE_MICROSECOND = timedelta(microseconds=1)


@runtime_checkable
class Clock(Protocol):
    """A source of the current time. now() must return a timezone-aware datetime."""

    def now(self) -> datetime: ...


class SystemClock:
    """The real clock, in UTC."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


def to_micros(moment: datetime) -> int:
    """Microseconds since the Unix epoch, by integer arithmetic. Rejects naive datetimes."""
    if not isinstance(moment, datetime):
        raise TypeError(f"expected a datetime, got {type(moment).__name__}")
    if moment.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return (moment - _EPOCH) // _ONE_MICROSECOND


def from_micros(micros: int) -> datetime:
    """The timezone-aware UTC datetime for microseconds since the Unix epoch (OverflowError outside years 1-9999)."""
    if not isinstance(micros, int) or isinstance(micros, bool):
        raise TypeError(f"expected an int, got {type(micros).__name__}")
    return _EPOCH + timedelta(microseconds=micros)
