"""Clock checks: UTC-aware system time, exact epoch conversion, a manual test clock, expiry boundaries."""

from datetime import date, datetime, timedelta, timezone, tzinfo

import pytest

from content_boundary_lab.clock import Clock, SystemClock, from_micros, to_micros

UTC = timezone.utc
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
ONE_MICROSECOND = timedelta(microseconds=1)

# Expected values are literals derived independently: calendar.timegm(...) * 10**6 + microseconds.
INSTANTS = [
    pytest.param(EPOCH, 0, id="unix-epoch"),
    pytest.param(datetime(2026, 11, 3, 12, 0, 0, 123457, tzinfo=UTC), 1793707200123457, id="2026-with-microseconds"),
    pytest.param(datetime(1969, 12, 31, 23, 59, 59, 999999, tzinfo=UTC), -1, id="one-microsecond-before-epoch"),
    pytest.param(datetime(1969, 12, 31, 23, 59, 58, 500000, tzinfo=UTC), -1500000, id="negative-fraction"),
    pytest.param(datetime(1900, 1, 1, tzinfo=UTC), -2208988800000000, id="1900"),
    pytest.param(datetime(2100, 1, 1, 0, 0, 0, 1, tzinfo=UTC), 4102444800000001, id="2100-plus-one-microsecond"),
    pytest.param(datetime(1, 1, 1, tzinfo=UTC), -62135596800000000, id="year-1"),
    pytest.param(datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC), 253402300799999999, id="year-9999-last-microsecond"),
]


class ManualClock:
    """Deterministic test clock: it stands still until it is set or advanced."""

    def __init__(self, start: datetime) -> None:
        self._now = start

    def now(self) -> datetime:
        return self._now

    def set(self, moment: datetime) -> None:
        self._now = moment

    def advance(self, delta: timedelta) -> None:
        self._now += delta


class _NoOffset(tzinfo):
    """A tzinfo that cannot say its UTC offset: Python treats such a datetime as naive."""

    def utcoffset(self, dt):
        return None

    def dst(self, dt):
        return None

    def tzname(self, dt):
        return None


def test_system_clock_returns_timezone_aware_utc():
    reference = datetime.now(UTC)
    now = SystemClock().now()
    assert now.utcoffset() == timedelta(0)
    assert abs(now - reference) < timedelta(minutes=1)
    assert isinstance(SystemClock(), Clock)


def test_unix_epoch_is_zero_microseconds():
    assert to_micros(EPOCH) == 0
    assert from_micros(0) == EPOCH


@pytest.mark.parametrize(("moment", "micros"), INSTANTS)
def test_conversion_is_exact_in_both_directions(moment, micros):
    assert to_micros(moment) == micros
    restored = from_micros(micros)
    assert restored == moment
    assert restored.utcoffset() == timedelta(0)


def test_every_sampled_microsecond_round_trips():
    base = datetime(2026, 11, 3, 12, 0, 0, tzinfo=UTC)
    for microsecond in [*range(0, 1_000_000, 997), 999_999]:
        moment = base.replace(microsecond=microsecond)
        assert to_micros(moment) == to_micros(base) + microsecond
        assert from_micros(to_micros(moment)) == moment
        assert from_micros(to_micros(moment)).microsecond == microsecond


@pytest.mark.parametrize("offset", [timedelta(hours=5, minutes=30), timedelta(hours=-8), timedelta(hours=14)])
def test_non_utc_offsets_represent_the_same_instant(offset):
    in_utc = datetime(2026, 11, 3, 12, 0, 0, 123457, tzinfo=UTC)
    local = in_utc.astimezone(timezone(offset))
    assert local.utcoffset() == offset
    assert to_micros(local) == to_micros(in_utc) == 1793707200123457
    assert from_micros(to_micros(local)) == local
    assert from_micros(to_micros(local)).utcoffset() == timedelta(0)


@pytest.mark.parametrize(
    "naive",
    [datetime(2026, 11, 3, 12), datetime(2026, 11, 3, 12, tzinfo=_NoOffset())],
    ids=["no-tzinfo", "tzinfo-without-offset"],
)
def test_naive_datetimes_are_rejected(naive):
    with pytest.raises(ValueError, match="timezone-aware"):
        to_micros(naive)


@pytest.mark.parametrize("value", ["2026-11-03T12:00:00+00:00", 1793707200, date(2026, 11, 3), None])
def test_to_micros_rejects_anything_but_a_datetime(value):
    with pytest.raises(TypeError, match="datetime"):
        to_micros(value)


@pytest.mark.parametrize("value", [1.5, 0.0, True, "0", None])
def test_from_micros_rejects_anything_but_an_integer(value):
    with pytest.raises(TypeError, match="int"):
        from_micros(value)


def test_the_whole_datetime_range_fits_a_64_bit_integer():
    lowest = to_micros(datetime.min.replace(tzinfo=UTC))
    highest = to_micros(datetime.max.replace(tzinfo=UTC))
    assert -(2**63) <= lowest and highest < 2**63
    assert from_micros(lowest) == datetime.min.replace(tzinfo=UTC)
    assert from_micros(highest) == datetime.max.replace(tzinfo=UTC)
    with pytest.raises(OverflowError):
        from_micros(highest + 1)
    with pytest.raises(OverflowError):
        from_micros(lowest - 1)


def test_manual_clock_is_deterministic_and_supports_set_and_advance():
    start = datetime(2026, 11, 3, 12, 0, 0, tzinfo=UTC)
    clock = ManualClock(start)
    assert isinstance(clock, Clock)
    assert clock.now() == start and clock.now() == start
    clock.advance(ONE_MICROSECOND)
    assert clock.now() == start + ONE_MICROSECOND
    clock.advance(timedelta(days=90))
    assert clock.now() == start + timedelta(days=90) + ONE_MICROSECOND
    later = datetime(2030, 1, 1, tzinfo=UTC)
    clock.set(later)
    assert clock.now() == later
    clock.set(start)
    assert clock.now() == start


@pytest.mark.parametrize(
    ("offset", "expired"),
    [(-ONE_MICROSECOND, False), (timedelta(0), True), (ONE_MICROSECOND, True)],
    ids=["one-microsecond-before", "at-the-boundary", "one-microsecond-after"],
)
def test_expiry_boundary_is_exact(offset, expired):
    # The approved rule (decisions section 4) is: an engagement is expired when now >= ends_at.
    ends_at = datetime(2026, 11, 3, 12, 0, 0, tzinfo=UTC)
    same_instant_elsewhere = ends_at.astimezone(timezone(timedelta(hours=5, minutes=30)))
    clock = ManualClock(ends_at)
    clock.advance(offset)
    assert (clock.now() >= ends_at) is expired
    assert (to_micros(clock.now()) >= to_micros(ends_at)) is expired
    assert (to_micros(clock.now()) >= to_micros(same_instant_elsewhere)) is expired
