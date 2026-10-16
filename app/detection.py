from collections import Counter


def detect_brute_force(events):
    failed_logins = [
        event for event in events
        if event.event_type == "failed_login"
    ]

    ip_counts = Counter(
        str(event.source_ip)
        for event in failed_logins
    )

    suspicious_ips = [
        ip for ip, count in ip_counts.items()
        if count >= 5
    ]

    return suspicious_ips