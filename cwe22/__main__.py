"""Command line: python3 -m cwe22 {setup,taie,llm,score,relax,agree,debate,checklist}.

Each step is resumable: completed cells in a run directory are skipped.
"""
import argparse
import sys
from datetime import datetime

from . import agreement, checklist, config, debate, llm, relax, report, taie, workspace


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

    p_relax = with_run(sub.add_parser("relax", help="hint relaxation: Tai-e and hinted LLM, levels Hinted-E"))
    p_relax.add_argument("--models", nargs="+", choices=list(config.MODELS), default=list(config.MODELS))
    p_relax.add_argument("--samples", type=int, default=config.SAMPLES, help="hinted requests per cell")
    p_relax.add_argument("--workers", type=int, default=8)
    p_relax.add_argument("--dry-run", action="store_true", help="local steps only; no API calls")
    p_relax.add_argument("--score", action="store_true", help="only write metrics.json and REPORT.md")
    p_relax.add_argument("--baseline", default=relax.BASELINE, help="baseline run whose hinted arm is the first level")

    p_agree = with_run(sub.add_parser("agree", help="agreement guard on every relaxation level, both revisions"))
    p_agree.add_argument("--relax-run", default="261020h", help="hint-relaxation run with the Tai-e flows")
    p_agree.add_argument("--readers", default="261020b", help="baseline run with the vanilla readers")
    p_agree.add_argument("--models", nargs="+", choices=list(config.MODELS), default=list(config.MODELS),
                         help="selection/driver models of the H2b and E configurations")
    p_agree.add_argument("--samples", type=int, default=config.SAMPLES, help="reader samples")

    p_debate = sub.add_parser("debate", help="multiagent debate (Du et al.) between the hinted LLMs, with an opposing agent")
    p_debate.add_argument("--run", default=datetime.now().strftime("%y%m%d-%H%M"), help="run name under results/")
    p_debate.add_argument("--relax-run", default="261020h", help="hint-relaxation run whose hinted answers are round 1")
    p_debate.add_argument("--levels", nargs="+", choices=relax.LEVELS, default=relax.LEVELS)
    p_debate.add_argument("--samples", type=int, default=config.SAMPLES)
    p_debate.add_argument("--agreement-runs", nargs="+", default=["261020r", "261020g"],
                          help="agreement-guard runs to filter with the debated answers")
    p_debate.add_argument("--workers", type=int, default=8)
    p_debate.add_argument("--dry-run", action="store_true", help="count calls and prompt sizes; no API calls")
    p_debate.add_argument("--score", action="store_true", help="only write metrics.json and REPORT.md")

    p_check = sub.add_parser("checklist", help="agreement guard + LLM-written CWE-22 checklist answered by Jev")
    p_check.add_argument("--run", default=datetime.now().strftime("%y%m%d-%H%M"), help="run name under results/")
    p_check.add_argument("--levels", nargs="+", choices=relax.LEVELS, default=relax.LEVELS)
    p_check.add_argument("--arms", nargs="+", choices=list(checklist.ARMS), default=list(checklist.ARMS))
    p_check.add_argument("--samples", type=int, default=config.SAMPLES)
    p_check.add_argument("--agreement-runs", nargs="+", default=["261020r", "261020g"],
                         help="agreement-guard runs whose priority tier is filtered")
    p_check.add_argument("--debate-run", default="261020d", help="debate run whose filter row is shown for comparison")
    p_check.add_argument("--workers", type=int, default=8)
    p_check.add_argument("--dry-run", action="store_true", help="count calls and code sizes; no API calls")
    p_check.add_argument("--score", action="store_true", help="only write metrics.json and REPORT.md")

    args = parser.parse_args(argv)
    config.require_data()
    if args.command == "setup":
        workspace.setup()
    elif args.command == "taie":
        taie.run(run_dir(args.run), args.projects, args.variants, args.heap, args.timeout, args.force)
    elif args.command == "llm":
        if args.samples < 1:
            parser.error("--samples must be positive")
        llm.run(run_dir(args.run), args.models, args.modes, args.projects, args.variants,
                args.samples, args.workers, args.dry_run)
    elif args.command == "relax":
        if args.samples < 1:
            parser.error("--samples must be positive")
        if not args.score:
            relax.execute(run_dir(args.run), args.projects, args.models, args.samples, args.dry_run, args.workers,
                          args.baseline)
        if not args.dry_run:
            result = relax.evaluate(run_dir(args.run), args.projects, args.models, args.samples, args.baseline)
            print((run_dir(args.run) / "REPORT.md").read_text())
            return 0 if all(a["summary"] for a in result["arms"]) else 1
    elif args.command == "agree":
        if args.samples < 1:
            parser.error("--samples must be positive")
        result = agreement.evaluate(run_dir(args.run), args.projects, args.models, args.samples,
                                    args.relax_run, args.readers)
        print((run_dir(args.run) / "REPORT.md").read_text())
        return 0 if all(a["summary"] for a in result["arms"]) else 1
    elif args.command == "debate":
        if not args.score and not debate.execute(run_dir(args.run), args.relax_run, args.samples, args.levels,
                                                 args.workers, args.dry_run):
            return 0 if args.dry_run else 1
        result = debate.evaluate(run_dir(args.run), args.relax_run, args.samples, args.levels, args.agreement_runs)
        print((run_dir(args.run) / "REPORT.md").read_text())
        return 0 if all(a["summary"] for a in result["arms"]) else 1
    elif args.command == "checklist":
        if not args.score and not checklist.execute(run_dir(args.run), args.samples, args.levels, args.arms,
                                                    args.agreement_runs, args.workers, args.dry_run):
            return 0 if args.dry_run else 1
        result = checklist.evaluate(run_dir(args.run), args.samples, args.levels, args.arms, args.agreement_runs,
                                    args.debate_run)
        print((run_dir(args.run) / "REPORT.md").read_text())
        return 0 if all(a["summary"] for a in result["arms"]) else 1
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
