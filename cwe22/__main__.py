"""Command line: python3 -m cwe22 {setup,taie,llm,score,relax,agree,pipeline,llmdfa,paper}.

Each step is resumable: completed cells in a run directory are skipped.
"""
import argparse
import sys
from datetime import datetime

from . import agreement, config, llm, llmdfa, paper, pipeline, relax, report, taie, workspace


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
    p_agree.add_argument("--readers", default="261021b", help="baseline run with the vanilla readers")
    p_agree.add_argument("--models", nargs="+", choices=list(config.MODELS), default=list(config.MODELS),
                         help="selection/driver models of the H2b and E configurations")
    p_agree.add_argument("--samples", type=int, default=config.SAMPLES, help="reader samples")

    p_pipe = sub.add_parser("pipeline", help="proposed pipeline: agreement guard -> Jev judge -> blind checklist")
    p_pipe.add_argument("--run", default="261021c", help="run name under results/")
    p_pipe.add_argument("--agreement-run", default="261021g", help="agreement run whose guard tier is filtered")
    p_pipe.add_argument("--relax-run", default="261020h", help="hint-relaxation run with the hinted answers")
    p_pipe.add_argument("--baseline", default=relax.BASELINE, help="baseline run whose hinted arm is the first level")
    p_pipe.add_argument("--levels", nargs="+", choices=relax.LEVELS, default=relax.LEVELS)
    p_pipe.add_argument("--samples", type=int, default=config.SAMPLES)
    p_pipe.add_argument("--workers", type=int, default=8)
    p_pipe.add_argument("--dry-run", action="store_true", help="count missing calls; no API calls")
    p_pipe.add_argument("--score", action="store_true", help="only write predictions.json, metrics.json and REPORT.md")

    p_dfa = sub.add_parser("llmdfa", help="LLMDFA (NeurIPS 2024) baseline on the Hinted level's inputs")
    p_dfa.add_argument("--run", default="261022l", help="run name under results/")
    p_dfa.add_argument("--setup", action="store_true", help="clone the pinned engine, create its venv, build the grammar")
    p_dfa.add_argument("--python", default=sys.executable, help="interpreter for LLMDFA's virtualenv (with --setup)")
    p_dfa.add_argument("--models", nargs="+", choices=list(llmdfa.MODELS), default=list(llmdfa.MODELS))
    p_dfa.add_argument("--samples", type=int, default=config.SAMPLES)
    p_dfa.add_argument("--projects", nargs="+", choices=config.PROJECTS, default=config.PROJECTS)
    p_dfa.add_argument("--workers", type=int, default=4, help="cases run at once")
    p_dfa.add_argument("--dry-run", action="store_true", help="write the plans and list the cases; no API calls")
    p_dfa.add_argument("--score", action="store_true", help="only write metrics.json and REPORT.md")

    p_paper = sub.add_parser("paper", help="LaTeX tables for the paper from saved runs")
    p_paper.add_argument("--out", default="paper", help="directory under results/ for the .tex files")
    p_paper.add_argument("--baseline", default="261021b")
    p_paper.add_argument("--relax-run", default="261020h")
    p_paper.add_argument("--pipeline-run", default="261021c")
    p_paper.add_argument("--llmdfa-run", default="261022l")

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
    elif args.command == "pipeline":
        if not args.score and not pipeline.execute(run_dir(args.run), args.agreement_run, args.relax_run, args.baseline,
                                                   args.samples, args.levels, args.workers, args.dry_run):
            return 0 if args.dry_run else 1
        result = pipeline.evaluate(run_dir(args.run), args.agreement_run, args.relax_run, args.baseline,
                                   args.samples, args.levels)
        print((run_dir(args.run) / "REPORT.md").read_text())
        return 0 if all(a["summary"] for a in result["arms"]) else 1
    elif args.command == "llmdfa":
        if args.setup:
            llmdfa.setup(args.python)
            return 0
        if not args.score and not llmdfa.execute(run_dir(args.run), args.models, args.samples, args.projects,
                                                 args.workers, args.dry_run):
            return 0 if args.dry_run else 1
        result = llmdfa.evaluate(run_dir(args.run), args.models, args.samples, args.projects)
        print((run_dir(args.run) / "llmdfa" / "REPORT.md").read_text())
        return 0 if all(a["summary"] for a in result["arms"]) else 1
    elif args.command == "paper":
        out = paper.write(run_dir(args.out), args.baseline, args.relax_run, args.pipeline_run, args.llmdfa_run)
        print("wrote {}/paper_tables.tex and paper_tables_main.tex".format(out))
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
