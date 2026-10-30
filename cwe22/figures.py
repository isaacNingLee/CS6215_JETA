"""Paper Figures 5, 6 and 8, drawn from the numbers paper.py computes (needs matplotlib).

* fig5_hint_relaxation.pdf  macro FDR, macro F1 and detected projects per hint level, per track
* fig6_pair_correct.pdf     pair-correct projects per hint level: Tai-e, hinted reader, JETA's stages
* fig8_cost_breakdown.pdf   JETA's model charges by component (Original configuration)

Shaded bands and error bars are one sample standard deviation over three runs; Tai-e runs once.
Each series also differs by line style, so identity never rests on color alone.
"""
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

LEVELS = ["Original", "H1", "H2a", "H2b", "E"]
STYLE = {  # color, line style
    "Tai-e": ("#555F66", (0, (4, 2))),
    "Hinted LLM": ("#1F6FA8", (0, (6, 2, 1, 2))),
    "Agreement": ("#8B6BBE", (0, (1, 1.5))),
    "+ judgment": ("#1A9A72", (0, (4, 2))),
    "+ checklist": ("#D9640F", "-"),
}
JETA = "+ checklist"  # JETA's final output is its last stage
COST_COLORS = ["#6A5ACD", "#7CC8A8", "#E8A88A", "#8FB3E0"]


def setup():
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 7, "axes.titlesize": 8,
                         "axes.spines.top": False, "axes.spines.right": False, "axes.edgecolor": "#9AA3A8",
                         "axes.grid": True, "axes.grid.axis": "y", "grid.color": "#E3E6E8", "grid.linewidth": 0.6,
                         "xtick.color": "#3A4248", "ytick.color": "#3A4248", "pdf.fonttype": 42})


def series(ax, levels, arm, key, label):
    color, dash = STYLE[arm]
    means = [levels[l][key][0] for l in LEVELS]
    sds = [levels[l][key][1] for l in LEVELS]
    x = range(len(LEVELS))
    if arm != "Tai-e":
        ax.fill_between(x, [m - s for m, s in zip(means, sds)], [m + s for m, s in zip(means, sds)],
                        color=color, alpha=0.12, lw=0)
        ax.errorbar(x, means, yerr=sds, fmt="none", ecolor=color, elinewidth=0.8, capsize=2)
    ax.plot(x, means, color=color, linestyle=dash, lw=1.6, marker="o", ms=6, mfc="white", mew=1.4, label=label,
            zorder=3)


def axis(ax, top, ticks, xlabel):
    ax.set_xticks(range(len(LEVELS)))
    ax.set_xticklabels(LEVELS)
    ax.set_ylim(-0.03 * top, top * 1.05)
    ax.set_yticks(ticks)
    if xlabel:
        ax.set_xlabel("Hint level")


def hint_relaxation(path, relaxation):
    panels = [("fdr", "Macro FDR (%)  ↓", 100, [0, 25, 50, 75, 100]),
              ("f1", "Macro F1 (%)  ↑", 100, [0, 25, 50, 75, 100]),
              ("det", "Detected projects (/6)  ↑", 6, [0, 2, 4, 6])]
    fig, axes = plt.subplots(2, 3, figsize=(6.8, 3.35), sharex=True)
    for row, (track, arms) in enumerate(relaxation.items()):
        for col, (key, title, top, ticks) in enumerate(panels):
            ax = axes[row][col]
            for arm, label in (("Tai-e", "Tai-e"), ("Hinted LLM", "Hinted LLM"), (JETA, "JETA")):
                series(ax, arms[arm], arm, key, label)
            axis(ax, top, ticks, row == 1)
            if row == 0:
                ax.set_title(title, weight="bold")
            if col == 0:
                ax.set_ylabel("{} track".format(track), weight="bold")
    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=3, frameon=False, bbox_to_anchor=(0.5, 1.02))
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)


def pair_correct(path, relaxation):
    fig, axes = plt.subplots(1, 2, figsize=(6.7, 2.0), sharey=True)
    for ax, (track, arms) in zip(axes, relaxation.items()):
        for arm in ("Tai-e", "Hinted LLM", "Agreement", "+ judgment", "+ checklist"):
            series(ax, arms[arm], arm, "pc", arm)
        axis(ax, 4, [0, 1, 2, 3, 4], True)
        ax.set_title("{} track".format(track), weight="bold")
    axes[0].set_ylabel("Pair-correct projects (/6)")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=5, frameon=False, bbox_to_anchor=(0.5, 1.06))
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)


def cost_breakdown(path, parts):
    names = list(parts)
    costs = [parts[n]["cost"] for n in names]
    fig = plt.figure(figsize=(2.7, 1.7))
    ax = fig.add_axes([0.0, 0.02, 0.55, 0.96])
    ax.pie(costs, colors=COST_COLORS, startangle=90, counterclock=False,
           wedgeprops=dict(width=0.32, edgecolor="white", linewidth=1.2))
    ax.text(0, 0.12, "TOTAL COST", ha="center", va="center", fontsize=6, color="#555F66")
    ax.text(0, -0.12, "${:.3f}".format(sum(costs)), ha="center", va="center", fontsize=9, weight="bold",
            color="#23313D")
    ax.set_aspect("equal")
    for i, (name, color) in enumerate(zip(names, COST_COLORS)):
        y = 0.86 - i * 0.24
        fig.patches.append(matplotlib.patches.Rectangle((0.6, y - 0.015), 0.04, 0.065, color=color,
                                                        transform=fig.transFigure, figure=fig))
        fig.text(0.67, y + 0.02, name, fontsize=6.5, va="center", color="#23313D")
        fig.text(0.67, y - 0.06, "{:.1%}  ·  ${:.3f}".format(parts[name]["share"], parts[name]["cost"]),
                 fontsize=5.5, va="center", color="#60717B")
    fig.savefig(path)
    plt.close(fig)


def draw(out, numbers):
    setup()
    relaxation = numbers["figure5_6_relaxation"]
    hint_relaxation(out / "fig5_hint_relaxation.pdf", relaxation)
    pair_correct(out / "fig6_pair_correct.pdf", relaxation)
    cost_breakdown(out / "fig8_cost_breakdown.pdf", numbers["figure8_cost_breakdown"])
