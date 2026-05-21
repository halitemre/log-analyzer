"""
Analyze IIS and/or WAS logs and send the summary to a local LM Studio LLM.

Usage:
    # IIS only
    uv run analyze.py --log-file sample-iis.log --model "google/gemma-4-e4b"

    # WAS only
    uv run analyze.py --was-file sample-was.log --model "google/gemma-4-e4b"

    # Both together
    uv run analyze.py --log-file sample-iis.log --was-file sample-was.log --model "google/gemma-4-e4b"

    # Directories (reads all *.log files in each)
    uv run analyze.py --log-dir "C:\\inetpub\\logs\\W3SVC1" --was-dir "C:\\logs\\was" --model "google/gemma-4-e4b"

    # Save report
    uv run analyze.py --log-file sample-iis.log --was-file sample-was.log --model "google/gemma-4-e4b" --output report.txt

    # Compare multiple models sequentially (load each model in LM Studio before confirming)
    uv run analyze.py --log-file sample-iis.log --models "model-a" "model-b" --output report.txt

LM Studio must be running with the local server enabled (default: http://localhost:1234).
Recommended CPU-only model: Phi-3 Mini Instruct Q4_K_M (~2.2 GB), google/gemma-4-e4b, or llama-3.2-3b-instruct.
"""

import argparse
import sys
from datetime import datetime, timezone

import requests

from aggregator import build_summary, render_text

LM_STUDIO_URL = "http://localhost:1234/v1/chat/completions"

SYSTEM_PROMPT = """\
You are a server operations analyst. Analyze the web server log summary below (IIS and/or WAS logs).

List findings as bullet points:
- Critical issues: high error rates, slow endpoints (high P95), 5xx spikes
- Suspicious activity: one IP with many errors, repeated 4xx, unusual user agents
- For each issue: one concrete action to take

Be brief. Only mention what the data actually shows.\
"""


def query_lm_studio(prompt: str, model: str) -> str:
    try:
        resp = requests.post(
            LM_STUDIO_URL,
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1024,
                "stream": False,
            },
            timeout=2400,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
    except requests.exceptions.ConnectionError:
        sys.exit(
            "ERROR: Cannot connect to LM Studio at http://localhost:1234\n"
            "Make sure LM Studio is running and the local server is enabled.\n"
            "In LM Studio: Local Server tab -> Start Server"
        )
    except requests.exceptions.HTTPError as e:
        sys.exit(
            f"ERROR: LM Studio returned an error: {e}\n"
            "Make sure the model is loaded in LM Studio before running."
        )


def save_report(path: str, model: str, log_block: str, analysis: str):
    report = (
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
        f"Model: {model}\n\n"
        f"--- LOG SUMMARY ---\n{log_block}\n"
        f"--- ANALYSIS ---\n{analysis}\n"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(report)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze IIS and/or WAS logs with a local LLM via LM Studio.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    iis_group = parser.add_argument_group("IIS logs")
    iis_ex = iis_group.add_mutually_exclusive_group()
    iis_ex.add_argument("--log-file", metavar="PATH", help="Path to a single IIS .log file")
    iis_ex.add_argument("--log-dir", metavar="DIR", help="Directory containing IIS .log files")
    iis_group.add_argument("--slow-ms", type=int, default=1000, metavar="MS",
                           help="IIS slow request threshold in ms (default: 1000)")

    was_group = parser.add_argument_group("WAS / app server logs")
    was_ex = was_group.add_mutually_exclusive_group()
    was_ex.add_argument("--was-file", metavar="PATH", help="Path to a single WAS .log file")
    was_ex.add_argument("--was-dir", metavar="DIR", help="Directory containing WAS .log files")
    was_group.add_argument("--was-slow-ms", type=int, default=1000, metavar="MS",
                           help="WAS slow request threshold in ms (default: 1000)")

    parser.add_argument("--window", type=int, default=500, metavar="MIN",
                        help="Time window in minutes (default: 500)")
    parser.add_argument("--top-n", type=int, default=15,
                        help="Top N items in ranked lists (default: 15)")
    parser.add_argument("--model", default="llama-3.2-3b-instruct",
                        help="Model identifier loaded in LM Studio (default: llama-3.2-3b-instruct)")
    parser.add_argument("--models", nargs="+", metavar="MODEL",
                        help="Multiple models to query sequentially")
    parser.add_argument("--output", metavar="FILE",
                        help="Save report(s) to this path (multi-model: appends _modelname.txt)")

    args = parser.parse_args()

    if not any([args.log_file, args.log_dir, args.was_file, args.was_dir]):
        parser.error("Provide at least one log source: --log-file/--log-dir (IIS) or --was-file/--was-dir (WAS)")

    models = args.models if args.models else [args.model]

    sources = []
    if args.log_file or args.log_dir:
        sources.append("IIS")
    if args.was_file or args.was_dir:
        sources.append("WAS")
    print(f"Aggregating {'+'.join(sources)} logs (window={args.window}min)...")

    summary = build_summary(
        iis_log_path=args.log_file,
        iis_log_dir=args.log_dir,
        iis_slow_threshold_ms=args.slow_ms,
        was_log_path=args.was_file,
        was_log_dir=args.was_dir,
        was_slow_threshold_ms=args.was_slow_ms,
        window_minutes=args.window,
        top_n=args.top_n,
    )

    log_block = render_text(summary)
    print("\n--- LOG SUMMARY SENT TO LLM ---")
    print(log_block)

    full_prompt = f"{SYSTEM_PROMPT}\n\n{log_block}"

    if len(models) == 1:
        model = models[0]
        print(f"\n--- ANALYSIS FROM {model.upper()} ---")
        analysis = query_lm_studio(full_prompt, model)
        print(analysis)
        if args.output:
            save_report(args.output, model, log_block, analysis)
            print(f"\nReport saved to: {args.output}")
        return

    # Sequential multi-model mode
    print(f"\nQuerying {len(models)} models sequentially...")
    results: dict[str, str] = {}
    for model in models:
        print(f"  -> Querying {model} ...")
        results[model] = query_lm_studio(full_prompt, model)
        print(f"  -> {model} done.")

    for model in models:
        print(f"\n{'='*60}")
        print(f"ANALYSIS FROM: {model}")
        print('='*60)
        print(results[model])

    if args.output:
        base = args.output.rsplit(".", 1)[0] if "." in args.output else args.output
        ext = args.output.rsplit(".", 1)[1] if "." in args.output else "txt"
        for model in models:
            safe_name = model.replace("/", "_").replace("\\", "_")
            path = f"{base}_{safe_name}.{ext}"
            save_report(path, model, log_block, results[model])
            print(f"Report saved to: {path}")

    print(f"\nDone. {len(models)} models queried.")


if __name__ == "__main__":
    main()
