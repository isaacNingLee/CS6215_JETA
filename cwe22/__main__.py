"""Command line: python3 -m cwe22 {setup,taie,llm,score}.

Each step is resumable: completed cells in a run directory are skipped.
"""
import argparse
import sys
from datetime import datetime

from . import config, llm, report, taie, workspace


def run_dir(name):
    return config.RESULTS / name


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python3 -m cwe22", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("setup", help="download Tai-e, Maven and the pinned dataset into $CS6215_WORK")

    def with_run(p):
        p.add_argument("--run", default=datetime.now().strftime("%y%m%d-%H%M"),
                       help="run name under results/ (default: new timestamp)")
        p.add_argument("--projects", nargs="+", choices=config.PROJECTS, default=config.PROJECTS)
        return p

    p_taie = with_run(sub.add_parser("taie", help="build subjects and run Tai-e"))
    p_taie.add_argument("--variants", nargs="+", choices=config.VARIANTS, default=config.VARIANTS)
    p_taie.add_argument("--heap", default="4g")
    p_taie.add_argument("--timeout", type=int, default=900, help="seconds per Tai-e analysis")
    p_taie.add_argument("--force", action="store_true", help="rerun cells that already have results")

    p_llm = with_run(sub.add_parser("llm", help="run vanilla/hinted LLM baselines via OpenRouter"))
    p_llm.add_argument("--variants", nargs="+", choices=config.VARIANTS, default=config.VARIANTS)
    p_llm.add_argument("--models", nargs="+", choices=list(config.MODELS), default=list(config.MODELS))
    p_llm.add_argument("--modes", nargs="+", choices=config.MODES, default=config.MODES)
    p_llm.add_argument("--samples", type=int, default=config.SAMPLES, help="requests per cell")
    p_llm.add_argument("--workers", type=int, default=8)
    p_llm.add_argument("--dry-run", action="store_true", help="build prompts only; no API calls")

    p_score = sub.add_parser("score", help="write metrics.json and REPORT.md for a run")
    p_score.add_argument("--run", required=True)
    p_score.add_argument("--samples", type=int, default=config.SAMPLES, help="LLM samples per cell")

    args = parser.parse_args(argv)
    if args.command == "setup":
        workspace.setup()
    elif args.command == "taie":
        taie.run(run_dir(args.run), args.projects, args.variants, args.heap, args.timeout, args.force)
    elif args.command == "llm":
        if args.samples < 1:
            parser.error("--samples must be positive")
        llm.run(run_dir(args.run), args.models, args.modes, args.projects, args.variants,
                args.samples, args.workers, args.dry_run)
    elif args.command == "score":
        result = report.evaluate(run_dir(args.run), samples=args.samples)
        print((run_dir(args.run) / "REPORT.md").read_text())
        return 0 if all(a["summary"] for a in result["arms"].values()) else 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        sys.exit(1)
