#!/usr/bin/env python3
"""
Paper figure generation script

Usage:
    python3 scripts/generate_paper_figures.py

Outputs PDF + PNG (300 DPI) to output/figures/.
"""

import pathlib
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# ---------------------------------------------------------------------------
# Global style
# ---------------------------------------------------------------------------
plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Hiragino Sans", "Hiragino Kaku Gothic ProN",
                         "Yu Gothic", "Meiryo", "sans-serif"],
    "font.size": 10,
    "axes.titlesize": 11,
    "axes.labelsize": 10,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 8.5,
    "figure.dpi": 150,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.05,
    "axes.grid": True,
    "grid.color": "#cccccc",
    "grid.linestyle": "--",
    "grid.linewidth": 0.5,
    "axes.axisbelow": True,
})

# Colorblind-friendly palette (Wong, 2011)
COLOR_ABLATION = "#0072B2"
COLOR_PROPOSED = "#D55E00"
COLOR_BASELINE = "#009E73"
COLOR_FPR = "#CC79A7"

COND_COLORS = {
    "A1": "#56B4E9",
    "A2": "#0072B2",
    "A3": "#004C7A",
    "A4": "#D55E00",
    "B1": "#009E73",
    "F1": "#E69F00",
    "ET": "#999999",
}

OUT_DIR = pathlib.Path("output/figures")


def _save(fig, name: str) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT_DIR / f"{name}.png")
    try:
        fig.savefig(OUT_DIR / f"{name}.pdf")
        print(f"  Saved {name}.pdf / .png")
    except UnicodeEncodeError:
        fig.savefig(OUT_DIR / f"{name}.svg")
        print(f"  Saved {name}.svg / .png (PDF skipped: CJK font issue)")
    plt.close(fig)


# ===================================================================
# Figure 1 -- 全条件比較（DR/TPR/FPR）
# ===================================================================
def figure1_main_results():
    labels = ["A1\nOneShot", "A2\nStateless", "A3\nReflexion",
              "A4\nProposed", "B1\nDirectLLM", "F1\nFALCON", "ET\nOpen"]
    dr   = [37.2, 77.9, 79.2, 81.7, 99.6, 45.9,  7.1]
    tpr  = [ 0.0, 82.6, 82.5, 81.7, 81.8,100.0, 15.5]
    fpr  = [ None, 6.3,  5.9,  5.9, 12.5,  0.0,  0.0]

    dr_err  = [2.5, 2.1, 3.1, 0.7, 0.4, 2.3, 0.0]
    tpr_err = [0.0, 1.5, 0.5, 1.2, 1.3, 0.0, 0.0]
    fpr_err = [0.0, 0.1, 0.7, 0.6, 0.5, 0.0, 0.0]

    bar_colors_dr  = [COND_COLORS[k] for k in ["A1","A2","A3","A4","B1","F1","ET"]]
    bar_colors_tpr = [matplotlib.colors.to_rgba(c, 0.55) for c in bar_colors_dr]

    x = np.arange(len(labels))
    w = 0.32

    fig, ax = plt.subplots(figsize=(7, 3.0))

    ax.bar(x - w/2, dr, w, yerr=dr_err, capsize=2.5,
           color=bar_colors_dr, edgecolor="white", linewidth=0.5,
           label="検出率 DR (%)", zorder=3)
    ax.bar(x + w/2, tpr, w, yerr=tpr_err, capsize=2.5,
           color=bar_colors_tpr, edgecolor="white", linewidth=0.5,
           label="真陽性率 TPR (%)", zorder=3)

    ax2 = ax.twinx()
    fpr_x = [i for i, v in enumerate(fpr) if v is not None]
    fpr_y = [v for v in fpr if v is not None]
    fpr_e = [fpr_err[i] for i in fpr_x]
    ax2.errorbar(fpr_x, fpr_y, yerr=fpr_e, fmt="D", color=COLOR_FPR,
                 markersize=5, capsize=2.5, label="偽陽性率 FPR (%)", zorder=4)
    ax2.set_ylabel("偽陽性率 FPR (%)", color=COLOR_FPR)
    ax2.set_ylim(-1, 20)
    ax2.tick_params(axis="y", colors=COLOR_FPR)
    ax2.spines["right"].set_color(COLOR_FPR)

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("検出率 DR / 真陽性率 TPR (%)")
    ax.set_ylim(0, 115)
    ax.set_title("全条件の検出率・真陽性率・偽陽性率の比較")

    h1, l1 = ax.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, loc="upper left", ncol=3, framealpha=0.9)

    ax.axvline(x=3.5, color="#aaaaaa", linewidth=0.8, linestyle=":")
    ax.annotate("Ablation条件", xy=(1.5, 110), ha="center", fontsize=8,
                fontstyle="italic", color="#555555")
    ax.annotate("ベースライン", xy=(5.0, 110), ha="center", fontsize=8,
                fontstyle="italic", color="#555555")

    fig.tight_layout()
    _save(fig, "fig1_main_results")


# ===================================================================
# Figure 2 -- テンプレート修正 + 検出レベルCEGIS
# ===================================================================
def figure2_template_fix():
    labels = ["A4\nProposed", "A4\nFix4", "A4\nFix4+SV\n(8B)", "A4\nFix4+SV\n(32B)"]
    tpr = [81.7, 92.2, 91.3, 93.0]
    fpr = [ 5.9,  1.4,  0.4,  1.1]

    x = np.arange(len(labels))
    w = 0.30

    fig, ax = plt.subplots(figsize=(3.5, 3.0))

    ax.bar(x - w/2, tpr, w, color=COLOR_PROPOSED,
           edgecolor="white", linewidth=0.5, label="TPR (%)", zorder=3)
    ax.bar(x + w/2, fpr, w, color=COLOR_FPR,
           edgecolor="white", linewidth=0.5, label="FPR (%)", zorder=3)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel("割合 (%)")
    ax.set_ylim(0, 118)
    ax.set_title("テンプレート修正 + 検出レベルCEGIS")
    ax.legend(loc="center right", framealpha=0.9)

    delta_tpr = [0, 92.2 - 81.7, 91.3 - 81.7, 93.0 - 81.7]
    delta_fpr = [0, 1.4 - 5.9, 0.4 - 5.9, 1.1 - 5.9]
    for i in range(1, len(labels)):
        ax.annotate(f"+{delta_tpr[i]:.1f}pp",
                    xy=(x[i] - w/2, tpr[i] + 2), ha="center",
                    fontsize=7, fontweight="bold", color="#333333")
        ax.annotate(f"{delta_fpr[i]:+.1f}pp",
                    xy=(x[i] + w/2, fpr[i] + 2), ha="center",
                    fontsize=7, fontweight="bold", color=COLOR_FPR)

    fig.tight_layout()
    _save(fig, "fig2_template_fix")


# ===================================================================
# Figure 3 -- CEGISリカバリ率 vs リグレッション率
# ===================================================================
def figure3_cegis_convergence():
    conditions = ["A1\nOneShot", "A2\nStateless", "A3\nReflexion", "A4\nProposed"]
    recovery   = [ 0.1, 40.2, 42.6, 43.9]
    regression = [31.7,  5.0,  4.0,  4.7]

    x = np.arange(len(conditions))
    w = 0.30

    fig, ax = plt.subplots(figsize=(3.5, 2.8))

    ax.bar(x - w/2, recovery, w, color=COLOR_ABLATION,
           edgecolor="white", linewidth=0.5, label="リカバリ率 (%)", zorder=3)
    ax.bar(x + w/2, regression, w, color="#E69F00",
           edgecolor="white", linewidth=0.5, label="リグレッション率 (%)", zorder=3)

    ax.set_xticks(x)
    ax.set_xticklabels(conditions, fontsize=8)
    ax.set_ylabel("割合 (%)")
    ax.set_ylim(0, 55)
    ax.set_title("CEGISリカバリ率 vs リグレッション率")
    ax.legend(loc="upper left", framealpha=0.9, fontsize=8)

    for i, (rec, reg) in enumerate(zip(recovery, regression)):
        ax.text(x[i] - w/2, rec + 1.0, f"{rec:.1f}", ha="center",
                fontsize=7, color="#333333")
        ax.text(x[i] + w/2, reg + 1.0, f"{reg:.1f}", ha="center",
                fontsize=7, color="#333333")

    fig.tight_layout()
    _save(fig, "fig3_cegis_convergence")


# ===================================================================
# Figure 4 -- ベニン検証値数kの影響
# ===================================================================
def figure4_ablation_k():
    k_vals = [0, 10, 20, 50, 100]
    dr     = [82.9, 82.5, 81.4, 81.7, 80.9]
    dr_err = [1.6, 0.7, 0.2, 1.0, 1.1]

    fig, ax = plt.subplots(figsize=(3.5, 2.5))

    ax.errorbar(k_vals, dr, yerr=dr_err, fmt="o-", color=COLOR_ABLATION,
                markersize=5, capsize=3, linewidth=1.5, zorder=3)

    ax.set_xlabel("ベニン検証値数 $k$")
    ax.set_ylabel("検出率 (%)")
    ax.set_title("ベニン検証の厳しさによる影響")
    ax.set_xticks(k_vals)
    ax.set_ylim(78, 86)

    spread = max(dr) - min(dr)
    ax.annotate(f"$\\Delta$ = {spread:.1f}pp",
                xy=(60, 83.8), fontsize=9, fontstyle="italic",
                color="#555555",
                bbox=dict(boxstyle="round,pad=0.3", fc="white",
                          ec="#cccccc", alpha=0.9))

    fig.tight_layout()
    _save(fig, "fig4_ablation_k")


# ===================================================================
# Figure 5 -- CEGIS反復収束曲線
# ===================================================================
def figure5_iteration_convergence():
    iters =      [0,   1,   2,   3,   4,   5,   6,   7,   8,   9]
    cumulative = [46,  62,  75,  81,  88,  93,  96,  96,  97, 100]

    fig, ax = plt.subplots(figsize=(3.5, 2.5))

    ax.plot(iters, cumulative, "o-", color=COLOR_PROPOSED, markersize=5,
            linewidth=1.8, zorder=3)
    ax.fill_between(iters, 0, cumulative, alpha=0.12, color=COLOR_PROPOSED)

    ax.axhline(y=46, color="#999999", linestyle=":", linewidth=0.8)
    ax.text(6.8, 48, "初回のみ (46%)", fontsize=7, color="#666666")

    ax.set_xlabel("CEGIS反復回数")
    ax.set_ylabel("累積成功率 (%)")
    ax.set_title("CEGIS収束曲線（A4 Proposed）")
    ax.set_xticks(iters)
    ax.set_ylim(0, 105)
    ax.set_xlim(-0.3, 9.5)

    fig.tight_layout()
    _save(fig, "fig5_iteration_convergence")


# ===================================================================
# Main
# ===================================================================
def main():
    print(f"Generating figures to {OUT_DIR.resolve()} ...")
    figure1_main_results()
    figure2_template_fix()
    figure3_cegis_convergence()
    figure4_ablation_k()
    figure5_iteration_convergence()
    print("Done.")


if __name__ == "__main__":
    main()
