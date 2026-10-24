"""LaTeX tables for the paper from saved outputs: appendix tables (paper_tables.tex) and their
main-paper summaries (paper_tables_main.tex).

Rows: Tai-e, vanilla and hinted LLMs (baseline run), every hint-relaxation level (relax run), and
the proposed pipeline (pipeline run, all flows): the agreement guard, + Jev judging the hinted
answers, + the blind checklist answered by Jev. Every row is scored here with one rule: a failed or empty output counts as 100% FDR, unlike
REPORT.md files, whose macro FDR averages nonempty outputs only.
"""
import statistics as st

from . import config, relax, report
from .scoring import score
from .subjects import fix_labels, manifest
from .util import read_json

NAMES = ["zip4j", "zt-zip", "spark", "Plexus-Arch.", "Plexus-Utils", "mpxj"]
MAIN_COLS = [("fdr", "mean", min), ("f1", "mean", max), ("det", "sum", max), ("flag", "sum", min), ("pc", "sum", max)]
LEVEL_NAMES = [("h1", "H1: kit only", "H1: kit only"),
               ("h2a", "H2a: kit + all candidate sources", "H2a: + all candidate sources"),
               ("h2b", "H2b: kit + LLM-selected sources", "H2b: + LLM-selected sources"),
               ("e", "E: LLM entry + kit + LLM-selected sources", "E: + LLM-written entry")]


# ---- statistics --------------------------------------------------------------
def sd(xs):
    return st.stdev(xs) if len(xs) > 1 else 0.0


def per_project(runs, j, k):
    return [r[j][k] for r in runs]


def macro(runs, k, agg="mean"):
    f = (lambda r: 100 * st.mean(c[k] for c in r)) if agg == "pct" else \
        (lambda r: sum(c[k] for c in r)) if agg == "sum" else (lambda r: st.mean(c[k] for c in r))
    return [f(r) for r in runs]


def fmt(xs, bold=False, sdv=True):
    mu = "%.1f" % st.mean(xs)
    if bold:
        mu = r"\mathbf{%s}" % mu
    return r"\msd{%s}{%.1f}" % (mu, sd(xs)) if sdv else (r"$%s$" % mu if bold else mu)


def best(rows, k, agg, pick):
    return pick(round(st.mean(macro(r, k, agg)), 1) for _, r in rows)


# ---- appendix tables -----------------------------------------------------------
MSD = r"""\newcommand{\msd}[2]{%
  \ensuremath{#1_{\scriptscriptstyle\pm #2}}%
}

\setlength{\tabcolsep}{3pt}
\renewcommand{\arraystretch}{1.35}
"""


def wide_head(sub, macro_sub, last):
    h = [r"\resizebox{\textwidth}{!}{%", r"\begin{tabular}{@{}l*{7}{cc}c@{}}", r"\toprule"]
    h += [r"& \multicolumn{2}{c}{\textbf{%s}}" % n for n in NAMES + ["Macro Avg."]]
    h += [r"& \textbf{%s} \\" % last[0]] + [r"\cmidrule(lr){%d-%d}" % (i, i + 1) for i in range(2, 16, 2)]
    h += ["", r"\textbf{Approach}"] + [r"& %s" % sub] * 6 + [r"& %s" % macro_sub, r"& %s \\" % last[1], r"\midrule", ""]
    return "\n".join(h)


def vuln_row(name, runs, bold):
    c = []
    for j in range(6):
        c += [fmt(per_project(runs, j, "fdr")), fmt(per_project(runs, j, "f1"))]
    c += [fmt(macro(runs, "fdr"), bold[0]), fmt(macro(runs, "f1"), bold[1]), fmt(macro(runs, "det", "sum"))]
    return name + "\n& " + "\n& ".join(" & ".join(c[i:i + 2]) for i in range(0, 14, 2)) + "\n& " + c[14] + r" \\"


def fixed_row(name, runs):
    c = []
    for j in range(6):
        c += [fmt(per_project(runs, j, "n")), "%.0f" % (100 * st.mean(per_project(runs, j, "flag")))]
    c += [fmt(macro(runs, "n")), fmt(macro(runs, "flag", "sum")), fmt(macro(runs, "pc", "sum"))]
    return name + "\n& " + "\n& ".join(" & ".join(c[i:i + 2]) for i in range(0, 14, 2)) + "\n& " + c[14] + r" \\"


def vuln_block(rows):
    b = (best(rows, "fdr", "mean", min), best(rows, "f1", "mean", max))
    return [vuln_row(n, r, (round(st.mean(macro(r, "fdr")), 1) == b[0], round(st.mean(macro(r, "f1")), 1) == b[1]))
            for n, r in rows]


def table(env, caption, label, body):
    return "\\begin{%s}[t]\n\\centering\n\\caption{%s}\n\\label{%s}\n\n" % (env, caption, label) + body + \
           "\n\\bottomrule\n\\end{tabular}%%\n}\n\\end{%s}\n" % env


COMMON = (r"Mean$_{\pm\mathrm{SD}}$ over three runs (percent for FDR and F1); a run with failed or empty output "
          r"counts as 100\% FDR. Tai-e is deterministic (one run).")
FIXDEF = (r"On the fixed revision the fix method has been patched, so any report of it is a false alarm. "
          r"$N$: locations reported; Flag: \% of runs that still report the fix method; "
          r"macro Flag: projects whose fix method is still reported (/6, lower is better); "
          r"P-C: pair-correct projects, whose fix method is reported on the vulnerable revision and not on the fixed one "
          r"(higher is better). A failed or empty output reports nothing. Tai-e is deterministic (one run).")
LEVELDEF = (r"Levels remove human input step by step: \emph{Original hint} uses the manual adapter and per-project "
            r"policy (LLM: prose hint and sink files); H1 replaces the policy with a shared CWE-22 kit; H2a adds every "
            r"candidate source; H2b keeps only the sources the model did not reject; E also replaces the manual adapter "
            r"with an LLM-written entry driver. At each level the hinted LLM sees the configuration Tai-e uses; "
            r"[Qwen]/[DeepSeek] marks the model that selected the sources or wrote the driver.")
GUARDDEF = (r"\emph{LLMDFA} (Wang et al., NeurIPS 2024; pinned upstream engine) gets the Original hint's "
            r"inputs: the manual source/sink policy as CWE-22 prompt specs and the Tai-e entry point; it parses the fix "
            r"file, sink files, entry class and adapter, and reports both endpoints of each validated trace. "
            r"\emph{Agreement guard}: Tai-e flows into a sink proven protected by a checked guard are set aside, then "
            r"the locations that Tai-e and at least one vanilla reader both report are kept (all Tai-e locations when "
            r"they share none). \emph{+ Jev (hinted answers)}: a location is kept when Jev, reading both hinted "
            r"LLMs' answers and the location's code, judges that they conclude it is part of the vulnerability. "
            r"\emph{+ checklist (Jev)}: a location is dropped when Jev answers yes to every condition of a safe "
            r"pattern in a CWE-22 checklist that DeepSeek wrote from CWE-22's description alone. Run $k$ uses sample "
            r"$k$ of every LLM input.")


def level_body(levels, rowfn):
    out = []
    for long, _, rows in levels:
        out.append(r"\multicolumn{16}{@{}l}{\textit{%s}} \\" % long + "\n" + "\n".join(rowfn(rows)))
    return "\n\\midrule\n".join(out)


# ---- main-paper tables ---------------------------------------------------------
MAIN_HEAD = r"""\newcommand{\msd}[2]{\ensuremath{#1_{\scriptscriptstyle\pm #2}}}
\setlength{\tabcolsep}{3.5pt}

\resizebox{\columnwidth}{!}{%
\begin{tabular}{@{}lccccc@{}}
\toprule
& \multicolumn{3}{c}{\textbf{Vulnerable}} & \textbf{Fixed} & \textbf{Pair} \\
\cmidrule(lr){2-4}\cmidrule(lr){5-5}\cmidrule(lr){6-6}
\textbf{FIRST} & FDR$\downarrow$ & F1$\uparrow$ & Det.$\uparrow$ & Flag.$\downarrow$ & P-C$\uparrow$ \\
\midrule
"""
MAINDEF = (r"Vulnerable: macro FDR and F1 (\%) and projects whose fix method is reported (Det., /6). "
           r"Fixed: projects whose already-patched fix method is still reported, a false alarm (Flag., /6). "
           r"Pair: P-C, projects whose fix method is reported on the vulnerable revision and not on the fixed one (/6). "
           r"A failed or empty output reports nothing, which lowers Flag. but not P-C. "
           r"Mean$_{\pm\mathrm{SD}}$ over three runs; Tai-e is deterministic. Bold: best per column")


def row_with(n, r, bests):
    cells = []
    for (k, agg, _), b in zip(MAIN_COLS, bests):
        xs = macro(r, k, agg)
        cells.append(fmt(xs, round(st.mean(xs), 1) == b, sdv=len(r) > 1))
    return n + " & " + " & ".join(cells) + r" \\"


def write(out, baseline="261021b", relax_run="261020h", pipeline_run="261021c", llmdfa_run="261022l"):
    projects = list(config.PROJECTS)
    info = manifest()
    labels = {p: fix_labels(info["subjects"][p]["slug"]) for p in projects}
    B, H = config.RESULTS / baseline, config.RESULTS / relax_run
    run = relax.Run(H, projects, ["qwen", "deepseek"], baseline=baseline)
    samples = [1, 2, 3]

    def cell(vloc, floc, p):
        v, f = score(vloc or [], labels[p]), score(floc or [], labels[p])
        return dict(fdr=100 * v["fdr"] if v["fdr"] is not None else 100.0, f1=100 * v["f1"], det=int(v["detected"]),
                    n=f["reported"], flag=int(f["detected"]), pc=int(v["detected"] and not f["detected"]))

    def arm(load, runs):
        return [[cell(load(p, "vulnerable", s), load(p, "fixed", s), p) for p in projects] for s in runs]

    def base(key):
        return arm(lambda p, v, s: report.load_locations(B, key, p, v, s)[0], [1] if key is None else samples)

    def taie(cfg):
        return arm(lambda p, v, s: relax.taie_locations(run, cfg, p, v, False)[0], [1])

    def hinted(short, level):
        return arm(lambda p, v, s: relax.hinted_locations(run, short, level, p, v, s)[0], samples)

    rows_by = {(r["config"], r["project"], r["variant"], r["sample"]): r
               for r in read_json(config.RESULTS / pipeline_run / "predictions.json") if not r["scoped"]}
    agreement_run = read_json(config.RESULTS / pipeline_run / "metrics.json")["agreement_run"]

    def stage(cfg, name):
        def load(p, v, s):
            row = rows_by[cfg, p, v, s]
            if row["status"] == "unscored":
                return None
            if row[name] is None:
                raise RuntimeError("Pipeline run {} lacks {} {} {} {} s{}".format(pipeline_run, name, cfg, p, v, s))
            return [tuple(x) for x in row[name]]
        return arm(load, samples)

    def proposed(cfg, tag=""):
        return [("Agreement guard" + tag, stage(cfg, "guard")), (r"\quad + Jev (hinted answers)", stage(cfg, "judged")),
                (r"\quad + checklist (Jev)", stage(cfg, "checked"))]

    def llmdfa(short):
        """LLMDFA cases (llmdfa.py); a failed case reports nothing."""
        def load(p, v, s):
            path = config.RESULTS / llmdfa_run / "llmdfa" / "{}-s{}".format(short, s) / "{}-{}".format(v, p) / "result.json"
            row = read_json(path)
            if row["status"] not in ("completed", "failed"):
                raise RuntimeError("LLMDFA case not finished: " + str(path))
            return [tuple(x) for x in row.get("locations", [])]
        return arm(load, samples)

    BASE = [[("Tai-e", base(None))],
            [("Vanilla Qwen", base(("qwen", "vanilla"))), ("Vanilla DeepSeek", base(("deepseek", "vanilla")))],
            [("Hinted Qwen", base(("qwen", "hinted"))), ("Hinted DeepSeek", base(("deepseek", "hinted")))],
            [("LLMDFA Qwen", llmdfa("qwen")), ("LLMDFA DeepSeek", llmdfa("deepseek"))],
            proposed("manual")]
    LEVELS = [("Original hint", "Original hint",
               [("Tai-e", taie("manual")), ("Hinted Qwen", BASE[2][0][1]), ("Hinted DeepSeek", BASE[2][1][1])]
               + BASE[3] + BASE[4])]
    for lv, long, short_name in LEVEL_NAMES:
        rows, guarded = [], []
        for s, cap in [("qwen", "Qwen"), ("deepseek", "DeepSeek")]:
            if lv in ("h1", "h2a") and s == "deepseek":
                continue
            tag = "" if lv in ("h1", "h2a") else " [%s]" % cap
            rows.append(("Tai-e" + tag, taie(relax.taie_config(lv, s))))
            guarded += proposed(relax.taie_config(lv, s), tag)
        rows += [("Hinted Qwen", hinted("qwen", lv)), ("Hinted DeepSeek", hinted("deepseek", lv))] + guarded
        LEVELS.append((long, short_name, rows))

    VH = wide_head("FDR & F1", "FDR & F1", ("Detected", "/6"))
    FH = wide_head("$N$ & Flag", "$N$ & Flag", ("P-C", "/6"))
    allbase = [x for g in BASE for x in g]
    bb = (best(allbase, "fdr", "mean", min), best(allbase, "f1", "mean", max))
    source = "% Generated by python3 -m cwe22 paper from results/{}, {}, {}, {} and {}.\n\n".format(
        baseline, relax_run, agreement_run, pipeline_run, llmdfa_run)
    app = [
        table("table*", r"CWE-22 fix-location detection across six Java projects. " + GUARDDEF + " " + COMMON,
              "tab:cwe22",
              MSD + "\n" + VH + "\n\n\\midrule\n\n".join("\n\n".join(
                  vuln_row(n, r, (round(st.mean(macro(r, "fdr")), 1) == bb[0],
                                  round(st.mean(macro(r, "f1")), 1) == bb[1]))
                  for n, r in g) for g in BASE)),
        table("table*", r"CWE-22 reports on the \emph{fixed} revisions of the six Java projects (arms as in "
              r"Table~\ref{tab:cwe22}). " + FIXDEF, "tab:cwe22-fixed",
              MSD + "\n" + FH + "\n\n\\midrule\n\n".join("\n\n".join(fixed_row(n, r) for n, r in g) for g in BASE)),
        table("table*", r"CWE-22 fix-location detection on the \emph{vulnerable} revisions under hint relaxation. "
              + LEVELDEF + " " + COMMON + " Bold marks the best macro score within each level.",
              "tab:cwe22-relax-vuln", MSD + "\n" + VH + level_body(LEVELS, vuln_block)),
        table("table*", r"CWE-22 reports on the \emph{fixed} revisions under hint relaxation (levels as in "
              r"Table~\ref{tab:cwe22-relax-vuln}). " + FIXDEF, "tab:cwe22-relax-fixed",
              MSD + "\n" + FH + level_body(LEVELS, lambda rows: [fixed_row(n, r) for n, r in rows])),
    ]
    out.mkdir(parents=True, exist_ok=True)
    (out / "paper_tables.tex").write_text(source + "\n\n".join(app))

    bests = [best(allbase, k, agg, pick) for k, agg, pick in MAIN_COLS]
    m1 = table("table", r"CWE-22 results on six Java projects (per-project scores in Tables~\ref{tab:cwe22} and "
               r"\ref{tab:cwe22-fixed}). " + GUARDDEF + " " + MAINDEF + ".", "tab:main-baselines",
               MAIN_HEAD.replace("FIRST", "Approach") + "\\midrule\n".join(
                   "\n".join(row_with(n, r, bests) for n, r in g) + "\n" for g in BASE))
    m2 = table("table", r"CWE-22 results under hint relaxation (per-project scores in Tables~\ref{tab:cwe22-relax-vuln} "
               r"and \ref{tab:cwe22-relax-fixed}). Each level removes one more human input, and the hinted LLM sees "
               r"the configuration Tai-e uses; [Q]/[D] marks the model that selected the sources (and wrote the entry "
               r"driver). " + MAINDEF + " within each level.", "tab:main-relax",
               MAIN_HEAD.replace("FIRST", "Level / approach") + "\n\\midrule\n".join(
                   r"\multicolumn{6}{@{}l}{\textit{%s}} \\" % short + "\n" + "\n".join(
                       row_with(n.replace("[Qwen]", "[Q]").replace("[DeepSeek]", "[D]"), r,
                                [best(rows, k, agg, pick) for k, agg, pick in MAIN_COLS]) for n, r in rows)
                   for _, short, rows in LEVELS))
    (out / "paper_tables_main.tex").write_text(source + m1 + "\n\n" + m2)
    return out
