from datetime import datetime, timedelta, timezone


def parse_timestamp(value):
    """Convert an ISO timestamp to UTC."""
    if not value:
        return None

    try:
        timestamp = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        else:
            timestamp = timestamp.astimezone(timezone.utc)

        return timestamp

    except (ValueError, TypeError):
        return None


def detect_brute_force(events, threshold=5, window_minutes=5):
    """
    Detect IP addresses with at least five failed logins
    within a five-minute window.
    """
    events_by_ip = {}

    for event in events:
        if event.event_type != "failed_login":
            continue

        ip = str(event.source_ip)
        timestamp = parse_timestamp(
            getattr(event, "timestamp", None)
        )

        if timestamp is None:
            continue

        if ip not in events_by_ip:
            events_by_ip[ip] = []

        events_by_ip[ip].append(timestamp)

    suspicious_ips = []
    window = timedelta(minutes=window_minutes)

    for ip, timestamps in events_by_ip.items():
        timestamps.sort()

        left = 0

        for right in range(len(timestamps)):
            while (
                timestamps[right] - timestamps[left]
                > window
            ):
                left += 1

            attempts = right - left + 1

            if attempts >= threshold:
                suspicious_ips.append(ip)
                break

    return suspicious_ips