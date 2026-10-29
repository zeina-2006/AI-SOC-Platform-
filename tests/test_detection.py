from datetime import datetime, timedelta
from types import SimpleNamespace

from app.detection import detect_brute_force


BASE_TIME = datetime(2026, 10, 16, 21, 0, 0)


def make_event(
    event_type,
    source_ip="192.168.1.100",
    minutes_after=0,
):
    timestamp = BASE_TIME + timedelta(
        minutes=minutes_after
    )

    return SimpleNamespace(
        event_type=event_type,
        source_ip=source_ip,
        timestamp=timestamp.isoformat(),
    )


def test_five_failed_logins_within_five_minutes_trigger_detection():
    events = [
        make_event("failed_login", minutes_after=minute)
        for minute in range(5)
    ]

    assert detect_brute_force(events) == [
        "192.168.1.100"
    ]


def test_four_failed_logins_do_not_trigger_detection():
    events = [
        make_event("failed_login", minutes_after=minute)
        for minute in range(4)
    ]

    assert detect_brute_force(events) == []


def test_failed_logins_outside_five_minute_window_do_not_trigger():
    events = [
        make_event("failed_login", minutes_after=minute)
        for minute in (0, 10, 20, 30, 40)
    ]

    assert detect_brute_force(events) == []


def test_successful_logins_do_not_trigger_detection():
    events = [
        make_event(
            "successful_login",
            minutes_after=minute,
        )
        for minute in range(10)
    ]

    assert detect_brute_force(events) == []


def test_different_ips_are_detected_independently():
    events = [
        make_event(
            "failed_login",
            "192.168.1.100",
            minute,
        )
        for minute in range(5)
    ]

    events += [
        make_event(
            "failed_login",
            "192.168.1.200",
            minute,
        )
        for minute in range(4)
    ]

    assert detect_brute_force(events) == [
        "192.168.1.100"
    ]


def test_empty_events_return_no_suspicious_ips():
    assert detect_brute_force([]) == []


def test_invalid_timestamps_are_ignored():
    events = [
        SimpleNamespace(
            event_type="failed_login",
            source_ip="192.168.1.100",
            timestamp="invalid timestamp",
        )
        for _ in range(5)
    ]

    assert detect_brute_force(events) == []