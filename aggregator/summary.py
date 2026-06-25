"""
Aggregates IIS and WAS log results into a plain-text or dict summary ready to be sent to an LLM.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from .iis import aggregate_iis, parse_iis_directory, parse_iis_log
from .was import aggregate_was, parse_was_directory, parse_was_log


def _fmt_bytes(n: int) -> str:
    if n >= 1_048_576:
        return f"{n / 1_048_576:.1f} MB"
    if n >= 1_024:
        return f"{n / 1_024:.1f} KB"
    return f"{n} B"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def build_summary(
    *,
    iis_log_path: Optional[str] = None,
    iis_log_dir: Optional[str] = None,
    iis_slow_threshold_ms: int = 1000,
    was_log_path: Optional[str] = None,
    was_log_dir: Optional[str] = None,
    was_slow_threshold_ms: int = 1000,
    window_minutes: int = 15,
    top_n: int = 15,
) -> dict:
    """
    Run IIS and/or WAS aggregation and return a combined summary dict.

    At least one of iis_log_path, iis_log_dir, was_log_path, or was_log_dir
    must be provided.

    Returns:
        {
            "generated_at":   ISO timestamp string,
            "window_minutes": int,
            "iis":            dict | None,
            "was":            dict | None,
        }
    """
    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

    iis_result = None
    if iis_log_path or iis_log_dir:
        if iis_log_dir:
            entries = parse_iis_directory(iis_log_dir, since=since)
        else:
            entries = parse_iis_log(iis_log_path, since=since)  # type: ignore[arg-type]
        iis_result = aggregate_iis(
            entries,
            slow_threshold_ms=iis_slow_threshold_ms,
            top_n=top_n,
        )

    was_result = None
    if was_log_path or was_log_dir:
        if was_log_dir:
            entries = parse_was_directory(was_log_dir, since=since)
        else:
            entries = parse_was_log(was_log_path, since=since)  # type: ignore[arg-type]
        was_result = aggregate_was(
            entries,
            slow_threshold_ms=was_slow_threshold_ms,
            top_n=top_n,
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window_minutes": window_minutes,
        "iis": iis_result,
        "was": was_result,
    }


# ---------------------------------------------------------------------------
# Text renderer — converts the summary dict into an LLM-friendly prompt block
# ---------------------------------------------------------------------------

def render_text(summary: dict, max_slow_endpoints: int = 10) -> str:
    """
    Render the summary dict as a compact plain-text block suitable for
    pasting directly into an LLM prompt.

    The output is intentionally terse to conserve tokens.
    """
    lines: list[str] = []
    ts = summary.get("generated_at", "")
    win = summary.get("window_minutes", 15)
    lines.append(f"=== Log Summary | window={win}min | generated={ts} ===\n")

    # ---- IIS section ----
    iis = summary.get("iis")
    if iis:
        lines.append("--- IIS ACCESS LOGS ---")
        lines.append(f"Total requests : {iis['total_requests']}")
        lines.append(
            f"4xx errors     : {iis['error_4xx_count']}  |  "
            f"5xx errors : {iis['error_5xx_count']}  |  "
            f"Error rate : {iis['error_rate_pct']}%"
        )
        lines.append(
            f"Slow requests (>{iis['slow_threshold_ms']}ms): "
            f"{iis['requests_above_threshold_ms']}"
        )
        lines.append(f"Status breakdown: {json.dumps(iis['status_summary'])}")

        if iis.get("substatus_summary"):
            lines.append(f"Substatus codes: {json.dumps(iis['substatus_summary'])}")

        if iis.get("win32_error_summary"):
            lines.append(f"Win32 errors   : {json.dumps(iis['win32_error_summary'])}")

        if iis.get("method_summary"):
            lines.append(f"HTTP methods   : {json.dumps(iis['method_summary'])}")

        if iis.get("total_bytes_sent") or iis.get("total_bytes_received"):
            lines.append(
                f"Bandwidth      : sent={_fmt_bytes(iis['total_bytes_sent'])}  "
                f"received={_fmt_bytes(iis['total_bytes_received'])}"
            )

        if iis["slow_endpoints"]:
            lines.append(
                f"\nTop {min(max_slow_endpoints, len(iis['slow_endpoints']))} "
                f"slow endpoints (by P95):"
            )
            for ep in iis["slow_endpoints"][:max_slow_endpoints]:
                lines.append(
                    f"  {ep['endpoint']:<45} "
                    f"reqs={ep['request_count']}  "
                    f"avg={ep['avg_ms']}ms  "
                    f"p95={ep['p95_ms']}ms  "
                    f"p99={ep['p99_ms']}ms  "
                    f"errors={ep['error_count']} ({ep['error_rate_pct']}%)"
                    + (f"  sent={_fmt_bytes(ep['bytes_sent'])}" if ep.get("bytes_sent") else "")
                )

        if iis.get("top_endpoints_by_bytes"):
            lines.append(f"\nTop {min(max_slow_endpoints, len(iis['top_endpoints_by_bytes']))} endpoints by bytes sent:")
            for ep in iis["top_endpoints_by_bytes"][:max_slow_endpoints]:
                lines.append(
                    f"  {ep['endpoint']:<45} "
                    f"sent={_fmt_bytes(ep['total_bytes_sent'])}  "
                    f"reqs={ep['request_count']}"
                )

        if iis.get("top_user_agents"):
            lines.append("\nTop user agents:")
            for ua in iis["top_user_agents"][:10]:
                lines.append(
                    f"  {ua['user_agent'][:60]:<60}  "
                    f"reqs={ua['count']}  "
                    f"errors={ua['error_count']} ({ua['error_rate_pct']}%)  "
                    f"sent={_fmt_bytes(ua['bytes_sent'])}"
                )

        if iis.get("top_usernames"):
            lines.append("\nTop authenticated users:")
            for u in iis["top_usernames"][:10]:
                lines.append(f"  {u['username']:<30}  reqs={u['count']}")

    # ---- WAS section ----
    was = summary.get("was")
    if was:
        lines.append("\n--- WAS / APP SERVER LOGS ---")
        lines.append(f"Total requests : {was['total_requests']}")
        lines.append(
            f"4xx errors     : {was['error_4xx_count']}  |  "
            f"5xx errors : {was['error_5xx_count']}  |  "
            f"Error rate : {was['error_rate_pct']}%"
        )
        if was.get("method_summary"):
            lines.append(f"HTTP methods   : {json.dumps(was['method_summary'])}")
        lines.append(f"Status breakdown: {json.dumps(was['status_summary'])}")

        if was["has_timing"]:
            lines.append(
                f"Slow requests (>{was['slow_threshold_ms']}ms): "
                f"{was['requests_above_threshold_ms']}"
            )

        if was["slow_endpoints"]:
            lines.append(
                f"\nTop {min(max_slow_endpoints, len(was['slow_endpoints']))} "
                f"slow endpoints (by P95):"
            )
            for ep in was["slow_endpoints"][:max_slow_endpoints]:
                line = (
                    f"  {ep['endpoint']:<45} "
                    f"reqs={ep['request_count']}  "
                    f"errors={ep['error_count']} ({ep['error_rate_pct']}%)"
                )
                if was["has_timing"]:
                    line += (
                        f"  avg={ep['avg_ms']}ms  "
                        f"p95={ep['p95_ms']}ms  "
                        f"p99={ep['p99_ms']}ms"
                    )
                lines.append(line)

        if was["top_ips"]:
            lines.append("\nTop IPs by request count:")
            for ip_entry in was["top_ips"][:10]:
                lines.append(
                    f"  {ip_entry['ip']:<20}  "
                    f"reqs={ip_entry['request_count']}  "
                    f"endpoints={ip_entry['unique_endpoints']}  "
                    f"errors={ip_entry['error_count']}"
                )

    lines.append("\n=== END OF SUMMARY ===")
    return "\n".join(lines)
