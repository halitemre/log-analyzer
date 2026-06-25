"""
Analyze IIS and/or WAS logs and send the summary to a local Ollama LLM.

Usage (Docker):
    docker compose run --rm log-analyzer --log-dir /logs/iis --model llama3.2:1b

Usage (local):
    python analyze.py --log-file sample-iis.log --model llama3.2:1b

    # Directories
    python analyze.py --log-dir /logs/iis --was-dir /logs/was --model llama3.2:1b

    # Save report
    python analyze.py --log-file sample-iis.log --model llama3.2:1b --output /output/report.txt

    # Compare multiple models sequentially
    python analyze.py --log-file sample-iis.log --models llama3.2:1b qwen2.5:3b --output /output/report.txt

LLM base URL is read from LLM_BASE_URL env var (default: http://localhost:11434).
In Docker the compose file sets LLM_BASE_URL=http://ollama:11434 automatically.
"""

import argparse
import os
import sys
from datetime import datetime, timezone

import requests

from aggregator import build_summary, render_text

_BASE_URL = os.environ.get("LLM_BASE_URL", "http://localhost:11434")
LLM_URL = f"{_BASE_URL}/v1/chat/completions"

SYSTEM_PROMPT = """\
You are a server operations analyst. Analyze the web server log summary below (IIS and/or WAS logs).

List findings as bullet points:
- Critical issues: high error rates, slow endpoints (high P95), 5xx spikes
- Suspicious activity: one IP with many errors, repeated 4xx, unusual user agents
- For each issue: one concrete action to take

Be brief. Only mention what the data actually shows.\
"""


def query_llm(prompt: str, model: str, no_thinking: bool = False) -> str:
    payload: dict = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 4096,
        "stream": False,
    }
    if no_thinking:
        payload["enable_thinking"] = False
    try:
        resp = requests.post(LLM_URL, json=payload, timeout=2400)
        resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        # Qwen3 thinking models may return content only in reasoning_content
        if not content:
            content = data["choices"][0]["message"].get("reasoning_content", "")
        return content or "(model returned empty response)"
    except requests.exceptions.ConnectionError:
        sys.exit(
            f"ERROR: Cannot connect to Ollama at {LLM_URL}\n"
            "Make sure Ollama is running. In Docker: docker compose up ollama -d"
        )
    except requests.exceptions.HTTPError as e:
        sys.exit(
            f"ERROR: Ollama returned an error: {e}\n"
            "Check the model is pulled: docker compose run --rm model-init"
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
        description="Analyze IIS and/or WAS logs with a local Ollama LLM.",
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

    parser.add_argument("--window", type=int, default=1440, metavar="MIN",
                        help="Time window in minutes (default: 1440)")
    parser.add_argument("--top-n", type=int, default=15,
                        help="Top N items in ranked lists (default: 15)")
    parser.add_argument("--model", default="qwen/qwen3.5-9b",
                        help="LLM model name (default: qwen/qwen3.5-9b)")
    parser.add_argument("--models", nargs="+", metavar="MODEL",
                        help="Multiple models to query sequentially")
    parser.add_argument("--output", metavar="FILE",
                        help="Save report(s) to this path (multi-model: appends _modelname.txt)")
    parser.add_argument("--no-thinking", action="store_true",
                        help="Disable thinking mode for Qwen3 and similar models")

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
        analysis = query_llm(full_prompt, model, no_thinking=args.no_thinking)
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
        results[model] = query_llm(full_prompt, model, no_thinking=args.no_thinking)
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
