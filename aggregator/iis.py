"""
IIS W3C extended log parser and aggregator.

IIS logs define their own field order via the #Fields: header line,
so this parser reads that first and maps columns dynamically.
time-taken is in milliseconds.
"""

import statistics
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_iis_log(
    log_path: str,
    since: Optional[datetime] = None,
) -> list[dict]:
    """
    Parse a single IIS W3C log file into a list of entry dicts.

    Each dict key matches the IIS field name exactly (e.g. 'c-ip',
    'cs-uri-stem', 'time-taken', 'sc-status'). A synthetic '_dt' key
    is added with a timezone-aware datetime.

    Args:
        log_path: Absolute or relative path to the .log file.
        since:    If given, entries older than this timestamp are skipped.
                  Must be timezone-aware (UTC recommended).
    """
    entries: list[dict] = []
    fields: list[str] = []

    with open(log_path, encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.rstrip("\r\n")

            if line.startswith("#Fields:"):
                fields = line[len("#Fields:"):].strip().split()
                continue

            if line.startswith("#") or not line.strip():
                continue

            if not fields:
                continue

            # IIS encodes spaces inside values as '+', so plain split is safe.
            parts = line.split(" ")
            if len(parts) < len(fields):
                continue

            # Extra columns (rare) are merged into the last field.
            if len(parts) > len(fields):
                parts = parts[: len(fields) - 1] + [" ".join(parts[len(fields) - 1 :])]

            entry = dict(zip(fields, parts))

            # Build a real datetime from the date + time columns.
            date_str = entry.get("date", "")
            time_str = entry.get("time", "")
            if date_str and time_str:
                try:
                    dt = datetime.strptime(
                        f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S"
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
            else:
                continue

            if since and dt < since:
                continue

            entry["_dt"] = dt
            entries.append(entry)

    return entries


def parse_iis_directory(
    log_dir: str,
    since: Optional[datetime] = None,
    glob_pattern: str = "*.log",
) -> list[dict]:
    """
    Parse all IIS log files in a directory, merged and sorted by time.

    Args:
        log_dir:      Directory containing IIS .log files.
        since:        Skip entries older than this (UTC-aware datetime).
        glob_pattern: File pattern; default '*.log'.
    """
    entries: list[dict] = []
    for path in sorted(Path(log_dir).glob(glob_pattern)):
        entries.extend(parse_iis_log(str(path), since=since))
    entries.sort(key=lambda e: e["_dt"])
    return entries


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    idx = max(0, int(len(sorted_values) * pct) - 1)
    return sorted_values[idx]


def aggregate_iis(
    entries: list[dict],
    slow_threshold_ms: int = 1000,
    top_n: int = 20,
) -> dict:
    """
    Aggregate a list of parsed IIS entries into a summary dict.

    Returns:
        {
            window_start:           datetime | None,
            window_end:             datetime | None,
            total_requests:         int,
            status_summary:         {status_code: count},
            error_4xx_count:        int,
            error_5xx_count:        int,
            error_rate_pct:         float,
            requests_above_threshold_ms: int,
            slow_threshold_ms:      int,
            slow_endpoints:         [top_n endpoints sorted by p95_ms desc],
            top_ips:                [top_n IPs sorted by request_count desc],
            top_user_agents:        [top 10 user agents],
        }

    Each slow_endpoint entry:
        {endpoint, request_count, avg_ms, p95_ms, p99_ms,
         error_count, error_rate_pct}

    Each top_ip entry:
        {ip, request_count, unique_endpoints, error_count}
    """
    if not entries:
        return _empty_iis_summary(slow_threshold_ms)

    endpoint_times: dict[str, list[int]] = defaultdict(list)
    endpoint_errors: dict[str, int] = defaultdict(int)
    ip_requests: dict[str, int] = defaultdict(int)
    ip_endpoints: dict[str, set] = defaultdict(set)
    ip_errors: dict[str, int] = defaultdict(int)
    status_counts: dict[str, int] = defaultdict(int)
    ua_counts: dict[str, int] = defaultdict(int)

    for e in entries:
        endpoint = e.get("cs-uri-stem", "-")
        status = e.get("sc-status", "-")
        ip = e.get("c-ip", "-")
        ua = e.get("cs(User-Agent)", "-")

        try:
            time_ms = int(e.get("time-taken", 0))
        except (ValueError, TypeError):
            time_ms = 0

        is_error = status and status[:1] in ("4", "5")

        endpoint_times[endpoint].append(time_ms)
        if is_error:
            endpoint_errors[endpoint] += 1

        ip_requests[ip] += 1
        ip_endpoints[ip].add(endpoint)
        if is_error:
            ip_errors[ip] += 1

        status_counts[status] += 1
        ua_counts[ua] += 1

    total = len(entries)

    # --- slow endpoints ---
    slow_endpoints = []
    for ep, times in endpoint_times.items():
        s = sorted(times)
        p95 = _percentile(s, 0.95)
        p99 = _percentile(s, 0.99)
        avg = statistics.mean(times)
        err = endpoint_errors[ep]
        slow_endpoints.append(
            {
                "endpoint": ep,
                "request_count": len(times),
                "avg_ms": round(avg),
                "p95_ms": int(p95),
                "p99_ms": int(p99),
                "error_count": err,
                "error_rate_pct": round(err / len(times) * 100, 1),
            }
        )
    slow_endpoints.sort(key=lambda x: x["p95_ms"], reverse=True)

    # --- top IPs ---
    top_ips = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)[:top_n]
    top_ips_detail = [
        {
            "ip": ip,
            "request_count": count,
            "unique_endpoints": len(ip_endpoints[ip]),
            "error_count": ip_errors[ip],
        }
        for ip, count in top_ips
    ]

    # --- top user agents ---
    top_uas = sorted(ua_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    error_4xx = sum(v for k, v in status_counts.items() if k.startswith("4"))
    error_5xx = sum(v for k, v in status_counts.items() if k.startswith("5"))

    window_start = entries[0]["_dt"] if entries else None
    window_end = entries[-1]["_dt"] if entries else None

    return {
        "window_start": window_start,
        "window_end": window_end,
        "total_requests": total,
        "status_summary": dict(sorted(status_counts.items())),
        "error_4xx_count": error_4xx,
        "error_5xx_count": error_5xx,
        "error_rate_pct": round((error_4xx + error_5xx) / total * 100, 1) if total else 0.0,
        "requests_above_threshold_ms": sum(
            1 for times in endpoint_times.values() for t in times if t >= slow_threshold_ms
        ),
        "slow_threshold_ms": slow_threshold_ms,
        "slow_endpoints": slow_endpoints[:top_n],
        "top_ips": top_ips_detail,
        "top_user_agents": [{"user_agent": ua, "count": c} for ua, c in top_uas],
    }


def _empty_iis_summary(slow_threshold_ms: int) -> dict:
    return {
        "window_start": None,
        "window_end": None,
        "total_requests": 0,
        "status_summary": {},
        "error_4xx_count": 0,
        "error_5xx_count": 0,
        "error_rate_pct": 0.0,
        "requests_above_threshold_ms": 0,
        "slow_threshold_ms": slow_threshold_ms,
        "slow_endpoints": [],
        "top_ips": [],
        "top_user_agents": [],
    }
