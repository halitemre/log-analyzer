"""
WAS / Apache Combined Log Format parser and aggregator.

Expected format (each line):
  IP - USER [DD/Mon/YYYY:HH:MM:SS +0000] "METHOD PATH PROTO" STATUS BYTES "REFERER" "UA" TIME_US

TIME_US is the last optional field (Apache %D — microseconds). If absent, latency
stats are skipped.
"""

import re
import statistics
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

_LINE_RE = re.compile(
    r'^(\S+)'            # 1  client IP
    r' \S+'              # ident (ignored)
    r' (\S+)'            # 2  auth user
    r' \[([^\]]+)\]'     # 3  timestamp
    r' "(\S+) (\S+) \S+"'  # 4 method, 5 path
    r' (\d+)'            # 6  status
    r' (\S+)'            # 7  bytes (may be "-")
    r' "([^"]*)"'        # 8  referer
    r' "([^"]*)"'        # 9  user agent
    r'(?: (\d+))?'       # 10 time in microseconds (optional)
)

_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_was_log(
    log_path: str,
    since: Optional[datetime] = None,
) -> list[dict]:
    """
    Parse a single WAS/Apache Combined log file into a list of entry dicts.

    Each dict contains:
        ip, user, method, path, status (str), bytes (int|None),
        referer, user_agent, time_us (int|None), _dt (datetime, UTC-aware)
    """
    entries: list[dict] = []

    with open(log_path, encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue

            m = _LINE_RE.match(line)
            if not m:
                continue

            ts_str = m.group(3)
            try:
                dt = datetime.strptime(ts_str, _TS_FORMAT).astimezone(timezone.utc)
            except ValueError:
                continue

            if since and dt < since:
                continue

            bytes_raw = m.group(7)
            time_raw = m.group(10)

            entries.append({
                "ip": m.group(1),
                "user": m.group(2),
                "method": m.group(4),
                "path": m.group(5),
                "status": m.group(6),
                "bytes": int(bytes_raw) if bytes_raw and bytes_raw != "-" else None,
                "referer": m.group(8),
                "user_agent": m.group(9),
                "time_us": int(time_raw) if time_raw else None,
                "_dt": dt,
            })

    return entries


def parse_was_directory(
    log_dir: str,
    since: Optional[datetime] = None,
    glob_pattern: str = "*.log",
) -> list[dict]:
    """Parse all WAS log files in a directory, merged and sorted by time."""
    entries: list[dict] = []
    for path in sorted(Path(log_dir).glob(glob_pattern)):
        entries.extend(parse_was_log(str(path), since=since))
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


def aggregate_was(
    entries: list[dict],
    slow_threshold_ms: int = 1000,
    top_n: int = 20,
) -> dict:
    """
    Aggregate a list of parsed WAS entries into a summary dict.

    Returns the same shape as aggregate_iis() so render_text() can use
    a shared renderer.

    time_us values are converted to milliseconds (divide by 1000).
    If no entry has time_us, latency fields are 0/empty.
    """
    if not entries:
        return _empty_was_summary(slow_threshold_ms)

    endpoint_times: dict[str, list[int]] = defaultdict(list)
    endpoint_errors: dict[str, int] = defaultdict(int)
    ip_requests: dict[str, int] = defaultdict(int)
    ip_endpoints: dict[str, set] = defaultdict(set)
    ip_errors: dict[str, int] = defaultdict(int)
    status_counts: dict[str, int] = defaultdict(int)
    ua_counts: dict[str, int] = defaultdict(int)
    method_counts: dict[str, int] = defaultdict(int)
    has_timing = False

    for e in entries:
        endpoint = e["path"]
        status = e["status"]
        ip = e["ip"]
        ua = e["user_agent"]

        time_ms = 0
        if e["time_us"] is not None:
            time_ms = e["time_us"] // 1000
            has_timing = True

        is_error = status and status[0] in ("4", "5")

        endpoint_times[endpoint].append(time_ms)
        if is_error:
            endpoint_errors[endpoint] += 1

        ip_requests[ip] += 1
        ip_endpoints[ip].add(endpoint)
        if is_error:
            ip_errors[ip] += 1

        status_counts[status] += 1
        ua_counts[ua] += 1
        method_counts[e["method"]] += 1

    total = len(entries)
    error_4xx = sum(v for k, v in status_counts.items() if k.startswith("4"))
    error_5xx = sum(v for k, v in status_counts.items() if k.startswith("5"))

    # --- slow endpoints ---
    slow_endpoints = []
    for ep, times in endpoint_times.items():
        s = sorted(times)
        p95 = _percentile(s, 0.95)
        p99 = _percentile(s, 0.99)
        avg = statistics.mean(times)
        err = endpoint_errors[ep]
        slow_endpoints.append({
            "endpoint": ep,
            "request_count": len(times),
            "avg_ms": round(avg),
            "p95_ms": int(p95),
            "p99_ms": int(p99),
            "error_count": err,
            "error_rate_pct": round(err / len(times) * 100, 1),
        })
    slow_endpoints.sort(key=lambda x: x["p95_ms"], reverse=True)

    # --- top IPs ---
    top_ips_raw = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)[:top_n]
    top_ips = [
        {
            "ip": ip,
            "request_count": count,
            "unique_endpoints": len(ip_endpoints[ip]),
            "error_count": ip_errors[ip],
        }
        for ip, count in top_ips_raw
    ]

    top_uas = sorted(ua_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "window_start": entries[0]["_dt"] if entries else None,
        "window_end": entries[-1]["_dt"] if entries else None,
        "total_requests": total,
        "status_summary": dict(sorted(status_counts.items())),
        "method_summary": dict(sorted(method_counts.items())),
        "error_4xx_count": error_4xx,
        "error_5xx_count": error_5xx,
        "error_rate_pct": round((error_4xx + error_5xx) / total * 100, 1) if total else 0.0,
        "requests_above_threshold_ms": (
            sum(1 for times in endpoint_times.values() for t in times if t >= slow_threshold_ms)
            if has_timing else 0
        ),
        "slow_threshold_ms": slow_threshold_ms,
        "has_timing": has_timing,
        "slow_endpoints": slow_endpoints[:top_n],
        "top_ips": top_ips,
        "top_user_agents": [{"user_agent": ua, "count": c} for ua, c in top_uas],
    }


def _empty_was_summary(slow_threshold_ms: int) -> dict:
    return {
        "window_start": None,
        "window_end": None,
        "total_requests": 0,
        "status_summary": {},
        "method_summary": {},
        "error_4xx_count": 0,
        "error_5xx_count": 0,
        "error_rate_pct": 0.0,
        "requests_above_threshold_ms": 0,
        "slow_threshold_ms": slow_threshold_ms,
        "has_timing": False,
        "slow_endpoints": [],
        "top_ips": [],
        "top_user_agents": [],
    }
