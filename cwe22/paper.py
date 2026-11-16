"""Every table, figure and quoted number of the report, regenerated from saved runs (no API call).

``python3 -m cwe22 paper`` writes to results/paper/:

* table1_main.tex        Table 1: per-project FDR, F1 and detections, Original configuration
* table2_ablation.tex    Table 2: incremental effect of JETA's stages on vulnerable and fixed revisions
* table3_cost.tex        Table 3: model calls, tokens, charges and time (cost.py)
* fig5_hint_relaxation.pdf, fig6_pair_correct.pdf, fig8_cost_breakdown.pdf   (figures.py; needs matplotlib)
* numbers.json           every number behind the tables and figures, and the case-study numbers in the text
* SUMMARY.md             the same numbers, readable, keyed to the paper's sections

Scoring convention (paper Section 5.2): a failed or empty output counts as 100% FDR. The REPORT.md of
each run instead averages FDR over nonempty outputs only, so its FDR can differ from the paper's.
Means and sample standard deviations are over the three aligned samples; Tai-e runs once.
"""
import json
import statistics as st

from . import config, cost, pipeline, relax, report
from .scoring import score
from .subjects import check_dataset, fix_labels, manifest
from .util import read_json, write_json

SAMPLES = list(range(1, config.SAMPLES + 1))
TRACKS = [("qwen", "Qwen"), ("deepseek", "DeepSeek")]
LEVEL_LABELS = {"hinted": "Original", "h1": "H1", "h2a": "H2a", "h2b": "H2b", "e": "E"}
PROJECT_LABELS = {"zip4j": "zip4j", "zt-zip": "zt-zip", "spark": "Spark", "plexus-archiver": "Plexus-Arch.",
                  "plexus-utils": "Plexus-Utils", "mpxj": "MPXJ"}
STAGE_LABELS = [("guard", "Agreement"), ("judged", "+ judgment"), ("checked", "+ checklist")]
MSD = r"\providecommand{\msd}[2]{\ensuremath{#1_{\scriptscriptstyle\pm #2}}}"


# ---- loading every arm ---------------------------------------------------------------------
class Scores:
    """Per-sample, per-project scores of every arm. An arm is a list (one per sample) of lists
    (one per project) of dicts: fdr, f1 (percent), det, flag, pc (0/1) and n (fixed-revision count)."""

    def __init__(self, baseline, relax_run, pipeline_run, llmdfa_run):
        info = manifest()
        check_dataset(info["dataset_commit"])
        self.projects = list(config.PROJECTS)
        self.labels = {p: fix_labels(info["subjects"][p]["slug"]) for p in self.projects}
        self.baseline = config.RESULTS / baseline
        self.relax = relax.Run(config.RESULTS / relax_run, self.projects, [s for s, _ in TRACKS], baseline=baseline)
        self.pipeline_run, self.llmdfa_run = pipeline_run, llmdfa_run
        self.metrics = read_json(config.RESULTS / pipeline_run / "metrics.json")
        self.stages = {(r["config"], r["project"], r["variant"], r["sample"]): r
                       for r in read_json(config.RESULTS / pipeline_run / "predictions.json")}

    def cell(self, vulnerable, fixed, project):
        v, f = score(vulnerable or [], self.labels[project]), score(fixed or [], self.labels[project])
        return dict(fdr=100 * v["fdr"] if v["fdr"] is not None else 100.0, f1=100 * v["f1"], det=int(v["detected"]),
                    n=f["reported"], flag=int(f["detected"]), pc=int(v["detected"] and not f["detected"]))

    def arm(self, load, samples=SAMPLES):
        return [[self.cell(load(p, "vulnerable", s), load(p, "fixed", s), p) for p in self.projects] for s in samples]

    def taie(self, cfg=None):
        """Tai-e on the baseline run (cfg None) or on one hint-relaxation configuration."""
        if cfg is None:
            return self.arm(lambda p, v, s: report.load_locations(self.baseline, None, p, v)[0], [1])
        return self.arm(lambda p, v, s: relax.taie_locations(self.relax, cfg, p, v)[0], [1])

    def reader(self, short, mode):
        return self.arm(lambda p, v, s: report.load_locations(self.baseline, (short, mode), p, v, s)[0])

    def hinted(self, short, level):
        return self.arm(lambda p, v, s: relax.hinted_locations(self.relax, short, level, p, v, s)[0])

    def jeta(self, cfg, stage="checked"):
        def load(p, v, s):
            row = self.stages[cfg, p, v, s]
            if row["status"] == "unscored":
                return None
            if row[stage] is None:
                raise RuntimeError("Pipeline run {} lacks {} {} {} {} s{}".format(
                    self.pipeline_run, stage, cfg, p, v, s))
            return [tuple(x) for x in row[stage]]
        return self.arm(load)

    def llmdfa(self, short):
        def load(p, v, s):
            path = (config.RESULTS / self.llmdfa_run / "llmdfa" / "{}-s{}".format(short, s) / "{}-{}".format(v, p)
                    / "result.json")
            row = read_json(path)
            if row["status"] not in ("completed", "failed"):
                raise RuntimeError("LLMDFA case not finished: " + str(path))
            return [tuple(x) for x in row.get("locations", [])]  # a failed case reports nothing
        return self.arm(load)


# ---- statistics ----------------------------------------------------------------------------
def per_sample(runs, key, agg="mean"):
    """Macro value of ``key`` in each sample: mean over projects, or a project count (sum)."""
    return [(sum if agg == "sum" else st.mean)(c[key] for c in r) for r in runs]


def mean_sd(xs):
    return st.mean(xs), (st.stdev(xs) if len(xs) > 1 else 0.0)


def summary(runs):
    """Macro FDR/F1 (%) and Det./Flag./P-C (projects) as [mean, sd]."""
    return {k: list(mean_sd(per_sample(runs, k, agg))) for k, agg in
            (("fdr", "mean"), ("f1", "mean"), ("det", "sum"), ("flag", "sum"), ("pc", "sum"))}


def r1(x):
    return round(x + 1e-9, 1)


# ---- LaTeX ---------------------------------------------------------------------------------
def value(xs, bold, deterministic):
    mu, sd = mean_sd(xs)
    text = "%.1f" % mu
    if deterministic:
        return r"\textbf{%s}" % text if bold else text
    return r"\msd{%s}{%.1f}" % (r"\mathbf{%s}" % text if bold else text, sd)


def table1(scores, groups):
    """Paper Table 1: per-project FDR, F1 and Det. (successful samples), then macro averages."""
    rows = [(name, runs) for group in groups for name, runs in group]
    project_values = lambda runs, j, key: [r[j][key] for r in runs]
    det_fraction = lambda runs, j: sum(project_values(runs, j, "det")) / len(runs)
    best = {}
    for j in range(len(scores.projects)):
        best[j, "fdr"] = min(r1(st.mean(project_values(r, j, "fdr"))) for _, r in rows)
        best[j, "f1"] = max(r1(st.mean(project_values(r, j, "f1"))) for _, r in rows)
        best[j, "det"] = max(det_fraction(r, j) for _, r in rows)
    for key, agg, pick in (("fdr", "mean", min), ("f1", "mean", max), ("det", "sum", max)):
        best["macro", key] = pick(r1(st.mean(per_sample(r, key, agg))) for _, r in rows)

    def row(name, runs):
        once = len(runs) == 1
        cells = []
        for j in range(len(scores.projects)):
            fdr, f1 = project_values(runs, j, "fdr"), project_values(runs, j, "f1")
            det = "%d/%d" % (sum(project_values(runs, j, "det")), len(runs))
            cells.append(" & ".join([value(fdr, r1(st.mean(fdr)) == best[j, "fdr"], once),
                                     value(f1, r1(st.mean(f1)) == best[j, "f1"], once),
                                     r"\textbf{%s}" % det if det_fraction(runs, j) == best[j, "det"] else det]))
        macro = []
        for key, agg in (("fdr", "mean"), ("f1", "mean"), ("det", "sum")):
            xs = per_sample(runs, key, agg)
            macro.append(value(xs, r1(st.mean(xs)) == best["macro", key], once))
        cells.append(" & ".join(macro))
        return name + "\n& " + "\n& ".join(cells) + r" \\"

    head = [r"\begin{table*}[t]", r"\centering",
            r"\caption{Comparison of Tai-e, direct LLM readers, adapted LLMDFA,",
            r"and JETA in locating methods changed by known CWE-22 fixes across",
            r"six vulnerable Java projects. Analysis hints come from manually",
            r"specified taint policies and entry points.}",
            r"\label{tab:main-results}", r"\setlength{\tabcolsep}{1.5pt}", r"\renewcommand{\arraystretch}{1.25}",
            r"\resizebox{\textwidth}{!}{%", r"\begin{tabular}{@{}l*{7}{ccc}@{}}", r"\toprule"]
    head += [r"& \multicolumn{3}{c}{\textbf{%s}}" % PROJECT_LABELS[p] for p in scores.projects]
    head += [r"& \multicolumn{3}{c}{\textbf{Macro avg.}} \\",
             r"\cmidrule(lr){2-4}\cmidrule(lr){5-7}\cmidrule(lr){8-10}",
             r"\cmidrule(lr){11-13}\cmidrule(lr){14-16}\cmidrule(lr){17-19}", r"\cmidrule(l){20-22}",
             r"\textbf{Approach}"]
    head += [r"& FDR$\downarrow$ & F1$\uparrow$ & Det."] * len(scores.projects)
    head += [r"& FDR$\downarrow$ & F1$\uparrow$ & Det.$\uparrow$ \\", r"\midrule"]
    body = []
    for i, group in enumerate(groups):
        if i:
            body.append(r"\midrule" if i == len(groups) - 1 else r"\addlinespace[2pt]")
        body += [row(name, runs) for name, runs in group]
    foot = [r"\bottomrule", r"\end{tabular}", "}", r"\par\smallskip", r"\begin{minipage}{\textwidth}", r"\footnotesize",
            r"FDR and F1 are percentages. Subscripts show sample standard deviations over three runs.",
            r"Bold marks the best mean, including ties.",
            r"Per-project Det. counts successful runs (Tai-e: one run);",
            r"macro Det. is the mean number of detected projects out of six.",
            r"Empty outputs receive 100\% FDR by convention.", r"\end{minipage}", r"\end{table*}"]
    return "\n".join([MSD] + head + body + foot) + "\n"


def table2(stages):
    """Paper Table 2: Agreement guard, + Jev judgment, + blind checklist (vulnerable and fixed revisions)."""
    cols = (("fdr", "mean", min), ("f1", "mean", max), ("det", "sum", max), ("flag", "sum", min), ("pc", "sum", max))
    best = [pick(r1(st.mean(per_sample(r, k, agg))) for _, r in stages) for k, agg, pick in cols]
    lines = [MSD, r"\begin{table}[!htbp]", r"\centering",
             r"\caption{Incremental effects of JETA stages under original hints. Each row adds a stage to the "
             r"preceding pipeline. On vulnerable revisions, FDR and F1 are macro percentages across six projects "
             r"and Det. counts detected projects. Flag. counts projects whose fixed revision still reports a "
             r"reference fix method; P-C counts pair-correct projects (\cref{sec:metrics}). Subscripts show sample "
             r"standard deviations over three aligned runs. Bold marks the best mean, including ties.}",
             r"\label{tab:ablation}", r"\small", r"\setlength{\tabcolsep}{2pt}",
             r"\begin{tabular*}{\columnwidth}{@{\extracolsep{\fill}}lccccc@{}}", r"\toprule",
             r"& \multicolumn{3}{c}{Vulnerable} & \multicolumn{2}{c}{Fixed / paired} \\",
             r"\cmidrule(lr){2-4}\cmidrule(l){5-6}",
             r"JETA stage & FDR$\downarrow$ & F1$\uparrow$ & Det.$\uparrow$ & Flag.$\downarrow$ & P-C$\uparrow$ \\",
             r"\midrule"]
    for name, runs in stages:
        cells = [value(per_sample(runs, k, agg), r1(st.mean(per_sample(runs, k, agg))) == b, False)
                 for (k, agg, _), b in zip(cols, best)]
        lines += [name, "& " + " & ".join(cells) + r" \\"]
    return "\n".join(lines + [r"\bottomrule", r"\end{tabular*}", r"\end{table}"]) + "\n"


def thousands(x, fmt):
    return format(x, fmt).replace(",", "{,}")


def table3(costs):
    """Paper Table 3: calls, tokens (k), total and per-run charges, and time per run."""
    lines = [r"\begin{table}[!htbp]", r"\centering",
             r"\caption{Model API charges and recorded time under manual policies and entry adapters, over 36 runs "
             r"(six projects $\times$ two revisions $\times$ three samples). Output tokens include reasoning.}",
             r"\label{tab:cost}", r"\footnotesize", r"\setlength{\tabcolsep}{2.5pt}",
             r"\begin{tabular*}{\columnwidth}{@{\extracolsep{\fill}}lrrrrrr@{}}", r"\toprule",
             r"& & \multicolumn{2}{c}{Tokens (k)} & \multicolumn{2}{c}{Cost} & Time \\",
             r"\cmidrule(lr){3-4}\cmidrule(lr){5-6}",
             r"Approach & Calls & In & Out & Total (\$) & /run (\textcent) & /run (s) \\", r"\midrule"]
    for name, row in costs["rows"]:
        tokens = ["--", "--"] if row["tokens_in"] is None else [
            thousands(row[k] / 1000, ",.1f") for k in ("tokens_in", "tokens_out")]
        if name in ("Hinted Qwen", "LLMDFA Qwen"):
            lines.append(r"\addlinespace[2pt]")
        if name == "JETA":
            lines.append(r"\midrule")
            name = r"\textbf{JETA}"
        lines.append(" & ".join([name, thousands(row["calls"], ",d")] + tokens + [
            "%.3f" % row["cost"], "%.3f" % row["cost_per_run_cents"], thousands(row["seconds_per_run"], ",.1f")])
            + r" \\")
    return "\n".join(lines + [r"\bottomrule", r"\end{tabular*}", r"\end{table}"]) + "\n"


# ---- case-study numbers quoted in the text ----------------------------------------------------
def location_in(locations, target):
    return target in {tuple(x) for x in locations or []}


def cases(scores, agreement_run):
    """Numbers of Figures 1, 4 and 7 and the case analysis (Sections 3, 4.2 and 5.5)."""
    zip_stream, unpack = ("InputStreamHelper", "processZipStream"), ("Unpacker", "process")
    guard = {(r["config"], r["project"], r["variant"], r["sample"]): r
             for r in read_json(config.RESULTS / agreement_run / "predictions.json")}
    out = {}
    g = guard["manual", "mpxj", "fixed", 1]
    out["mpxj_fixed_original"] = dict(
        taie_flows=g["flows"] + g["guarded"], guard_removed=g["guarded"],
        hinted_qwen_flags_fix_method=sum(location_in(relax.hinted_locations(scores.relax, "qwen", "hinted", "mpxj",
                                                                            "fixed", s)[0], zip_stream)
                                         for s in SAMPLES),
        jeta_suppressed=sum(not location_in(scores.stages["manual", "mpxj", "fixed", s]["checked"], zip_stream)
                            for s in SAMPLES),
        jeta_reports_vulnerable=sum(location_in(scores.stages["manual", "mpxj", "vulnerable", s]["checked"],
                                                zip_stream) for s in SAMPLES))
    spark = lambda load: sum(scores.cell(load(s), [], "spark")["det"] for s in SAMPLES)
    out["spark_vulnerable_detections"] = {
        "{} {}".format(mode, name): spark(lambda s: report.load_locations(scores.baseline, (short, mode), "spark",
                                                                          "vulnerable", s)[0])
        for mode in ("vanilla", "hinted") for short, name in TRACKS}
    run = pipeline.Run(config.RESULTS / scores.pipeline_run, scores.relax.dir.name, scores.relax.baseline.name)
    patterns, _ = run.checklist(1)
    groups, _ = pipeline.question_ids(patterns)
    figure4 = dict(pattern=patterns[0][0], conditions=patterns[0][1])
    for variant in config.VARIANTS:
        code = read_json(run.out / "context" / "mpxj-{}.json".format(variant))["locations"]["{}.{}".format(*zip_stream)]
        answers = read_json(run.checklist_answer_path(code, 1))["response"]["answers"]
        figure4[variant] = dict(scores=[answers[q]["noul"] for q in groups[0]],
                                suppressed=any(all(answers[q]["noul"] >= pipeline.THRESHOLD for q in ids)
                                               for ids in groups))
    out["figure4_mpxj_checklist_sample1"] = figure4
    cfg = relax.taie_config("e", "qwen")
    flows = read_json(scores.relax.taie_path(cfg, "mpxj", "vulnerable"))["flows"]
    out["mpxj_vulnerable_e_qwen"] = dict(
        taie_flows=len(flows),
        fix_method_in_taie_endpoints=location_in(relax.taie_locations(scores.relax, cfg, "mpxj", "vulnerable")[0],
                                                 zip_stream),
        fix_method_in_review_tail=sum(location_in(guard[cfg, "mpxj", "vulnerable", s]["tail"], zip_stream)
                                      for s in SAMPLES),
        jeta_detects=sum(location_in(scores.stages[cfg, "mpxj", "vulnerable", s]["checked"], zip_stream)
                         for s in SAMPLES))
    out["ztzip_fixed_jeta_flags_unpacker_process"] = sum(
        location_in(scores.stages["manual", "zt-zip", "fixed", s]["checked"], unpack) for s in SAMPLES)
    checked = scores.jeta("manual")
    out["original_pair_correct_samples_per_project"] = {
        p: sum(r[j]["pc"] for r in checked) for j, p in enumerate(scores.projects)}
    return out


# ---- everything --------------------------------------------------------------------------------
def write(out, baseline="261021b", relax_run="261020h", pipeline_run="261021c", llmdfa_run="261022l"):
    scores = Scores(baseline, relax_run, pipeline_run, llmdfa_run)
    agreement_run = scores.metrics["agreement_run"]
    main = [[("Tai-e", scores.taie())],
            [("Vanilla Qwen", scores.reader("qwen", "vanilla")), ("Vanilla DeepSeek", scores.reader("deepseek", "vanilla"))],
            [("Hinted Qwen", scores.reader("qwen", "hinted")), ("Hinted DeepSeek", scores.reader("deepseek", "hinted"))],
            [("LLMDFA Qwen", scores.llmdfa("qwen")), ("LLMDFA DeepSeek", scores.llmdfa("deepseek"))],
            [(r"\textbf{JETA}", scores.jeta("manual"))]]
    ablation = [("Agreement guard", scores.jeta("manual", "guard")),
                (r"\quad + Jev judgment", scores.jeta("manual", "judged")),
                (r"\quad + blind checklist", scores.jeta("manual", "checked"))]
    relaxation = {}
    for short, name in TRACKS:
        track = relaxation.setdefault(name, {})
        for level in relax.LEVELS:
            cfg = relax.taie_config(level, short)
            arms = [("Tai-e", scores.taie(cfg)), ("Hinted LLM", scores.hinted(short, level))]
            arms += [(label, scores.jeta(cfg, stage)) for stage, label in STAGE_LABELS]
            for label, runs in arms:
                track.setdefault(label, {})[LEVEL_LABELS[level]] = summary(runs)
            track.setdefault("config", {})[LEVEL_LABELS[level]] = cfg
    costs = cost.table(baseline, relax_run, agreement_run, pipeline_run, llmdfa_run)
    numbers = dict(
        sources=dict(baseline=baseline, relax=relax_run, agreement=agreement_run, pipeline=pipeline_run,
                     llmdfa=llmdfa_run),
        convention="mean and sample SD over 3 aligned samples; FDR/F1 in percent; empty output = 100% FDR",
        table1={name.replace(r"\textbf{JETA}", "JETA"): dict(
            macro=summary(runs), per_project={p: dict(fdr=mean_sd([r[j]["fdr"] for r in runs]),
                                                      f1=mean_sd([r[j]["f1"] for r in runs]),
                                                      detected="%d/%d" % (sum(r[j]["det"] for r in runs), len(runs)))
                                              for j, p in enumerate(scores.projects)})
            for group in main for name, runs in group},
        table2_ablation={name.replace(r"\quad ", ""): summary(runs) for name, runs in ablation},
        figure5_6_relaxation=relaxation,
        table3_cost=dict(runs=costs["runs"], rows=dict(costs["rows"])),
        # Figure 8 shares are of the rounded components' sum ($0.979), as its caption states.
        figure8_cost_breakdown={name: dict(cost=part["cost"], calls=part["calls"],
                                           share=round(part["cost"], 3) / sum(round(x["cost"], 3)
                                                                              for _, x in costs["jeta_parts"]))
                                for name, part in costs["jeta_parts"]},
        cases=cases(scores, agreement_run))
    out.mkdir(parents=True, exist_ok=True)
    stamp = "% Generated by python3 -m cwe22 paper from results/{}, {}, {}, {} and {}.\n".format(
        baseline, relax_run, agreement_run, pipeline_run, llmdfa_run)
    (out / "table1_main.tex").write_text(stamp + table1(scores, main))
    (out / "table2_ablation.tex").write_text(stamp + table2(ablation))
    (out / "table3_cost.tex").write_text(stamp + table3(costs))
    write_json(out / "numbers.json", numbers)
    (out / "SUMMARY.md").write_text(render(numbers))
    try:
        from . import figures
    except ImportError as exc:  # matplotlib is optional: tables and numbers do not need it
        print("Skipped figures ({}); install matplotlib to draw them".format(exc))
    else:
        figures.draw(out, numbers)
    return out


def render(numbers):
    """SUMMARY.md: the numbers the paper quotes, next to where it quotes them."""
    def ms(pair, digits=1):
        return "{0:.{2}f} ± {1:.{2}f}".format(pair[0], pair[1], digits)

    lines = ["# Paper numbers", "", "Generated by `python3 -m cwe22 paper` from saved runs ({}). {}.".format(
        ", ".join("{} `{}`".format(k, v) for k, v in numbers["sources"].items()), numbers["convention"].capitalize()),
             "", "## Table 1 (Section 5.3): Original configuration, vulnerable revisions", "",
             "| Approach | Macro FDR ↓ | Macro F1 ↑ | Det. ↑ | Per-project detections |", "| --- | ---: | ---: | ---: | --- |"]
    for name, row in numbers["table1"].items():
        m = row["macro"]
        lines.append("| {} | {} | {} | {} | {} |".format(name, ms(m["fdr"]), ms(m["f1"]), ms(m["det"]), ", ".join(
            "{} {}".format(PROJECT_LABELS[p], v["detected"]) for p, v in row["per_project"].items())))
    lines += ["", "## Table 2 (Section 5.6): JETA stages, Original configuration", "",
              "| Stage | FDR ↓ | F1 ↑ | Det. ↑ | Fixed: Flag. ↓ | P-C ↑ |", "| --- | ---: | ---: | ---: | ---: | ---: |"]
    lines += ["| {} | {} | {} | {} | {} | {} |".format(n, *(ms(s[k]) for k in ("fdr", "f1", "det", "flag", "pc")))
              for n, s in numbers["table2_ablation"].items()]
    lines += ["", "## Figures 5 and 6 (Section 5.4): hint relaxation", "",
              "Each track uses that model as the hinted reader and, at H2b and E, as the source selector and",
              "entry-driver writer. JETA (= + checklist) always uses both readers.", ""]
    for track, arms in numbers["figure5_6_relaxation"].items():
        lines += ["### {} track".format(track), "",
                  "| Arm | Level | Tai-e config | FDR ↓ | F1 ↑ | Det. ↑ | Flag. ↓ | P-C ↑ |",
                  "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |"]
        for arm, levels in arms.items():
            if arm == "config":
                continue
            lines += ["| {} | {} | `{}` | {} | {} | {} | {} | {} |".format(
                arm, level, arms["config"][level], *(ms(s[k]) for k in ("fdr", "f1", "det", "flag", "pc")))
                for level, s in levels.items()]
        lines.append("")
    lines += ["## Table 3 and Figure 8 (Section 5.7): cost over {} runs".format(numbers["table3_cost"]["runs"]), "",
              "| Approach | Calls | Tokens in (k) | Tokens out (k) | Total ($) | /run (¢) | /run (s) |",
              "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for name, r in numbers["table3_cost"]["rows"].items():
        tok = ["–", "–"] if r["tokens_in"] is None else ["{:,.1f}".format(r[k] / 1000) for k in ("tokens_in", "tokens_out")]
        lines.append("| {} | {:,} | {} | {} | {:.3f} | {:.3f} | {:,.1f} |".format(
            name, r["calls"], *tok, r["cost"], r["cost_per_run_cents"], r["seconds_per_run"]))
    lines += ["", "JETA's charges: " + "; ".join("{} {:.1%} (${:.3f}, {} calls)".format(n, p["share"], p["cost"], p["calls"])
                                                for n, p in numbers["figure8_cost_breakdown"].items()) + ".", "",
              "## Case numbers (Sections 3, 4.2, 5.5; Figures 1, 4, 7)", "", "```json"]
    lines += [json.dumps(numbers["cases"], indent=2), "```", ""]
    return "\n".join(lines)
