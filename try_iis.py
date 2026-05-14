from aggregator import build_summary, render_text

summary = build_summary(
    iis_log_path="sample.log",
    iis_slow_threshold_ms=1000,
    window_minutes=60 * 24,  # wide window so all sample entries are included
    top_n=10,
)

print(render_text(summary))
