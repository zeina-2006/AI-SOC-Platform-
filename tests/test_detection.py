from types import SimpleNamespace

from app.detection import detect_brute_force


def make_event(event_type, source_ip="192.168.1.100"):
    return SimpleNamespace(
        event_type=event_type,
        source_ip=source_ip,
    )


def test_five_failed_logins_detect_brute_force():
    events = [
        make_event("failed_login")
        for _ in range(5)
    ]

    result = detect_brute_force(events)

    assert result == ["192.168.1.100"]


def test_four_failed_logins_do_not_trigger_detection():
    events = [
        make_event("failed_login")
        for _ in range(4)
    ]

    result = detect_brute_force(events)

    assert result == []


def test_successful_logins_do_not_trigger_detection():
    events = [
        make_event("successful_login")
        for _ in range(10)
    ]

    result = detect_brute_force(events)

    assert result == []


def test_different_ips_are_detected_independently():
    events = [
        make_event("failed_login", "192.168.1.100")
        for _ in range(5)
    ]

    events += [
        make_event("failed_login", "192.168.1.200")
        for _ in range(4)
    ]

    result = detect_brute_force(events)

    assert result == ["192.168.1.100"]


def test_empty_events_return_no_suspicious_ips():
    result = detect_brute_force([])

    assert result == []