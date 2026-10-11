"""
Publication-Quality Visualization Generator for QSC.
Generates all 6 required publication-grade figures in results/figures/:
  1. Handshake Sequence & Wire Framing Diagram
  2. Handshake Latency Comparison (Platform A vs. B vs. D) with bootstrap error bars
  3. Memory Footprint & Allocation Timeline (RSS and Heap)
  4. Wire Overhead Analysis: PQC vs. Classical ECDH/ECDSA
  5. Transfer Throughput vs. Payload Size (1 KB, 100 KB, 10 MB)
  6. Platform D Trade-off Analysis (MTU fragmentation penalty Pareto chart)
"""

from __future__ import annotations

import os
import sys
import json
from pathlib import Path
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Apply clean publication-ready styling
plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
plt.rcParams.update({
    "font.family": "sans-serif",
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.labelsize": 12,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "figure.titlesize": 14,
    "figure.dpi": 300,
})


def plot_fig1_wire_framing(output_path: str = "results/figures/fig1_handshake_wire_framing.png"):
    """Figure 1: Handshake Sequence & Symmetric Chunk Wire Layout Diagram."""
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, 7), gridspec_kw={"height_ratios": [1.4, 1]})

    # Top: Protocol Sequence Flow
    ax1.set_xlim(0, 10)
    ax1.set_ylim(0, 10)
    ax1.axis("off")
    ax1.set_title("QSC 1-RTT Mutually Authenticated Handshake Protocol Flow", weight="bold", pad=12)

    # Peer swimlanes
    ax1.plot([2, 2], [1, 9], color="#2b5c8f", lw=2.5, linestyle="--")
    ax1.plot([8, 8], [1, 9], color="#8f2b2b", lw=2.5, linestyle="--")
    ax1.text(2, 9.3, "Client Node\n(Pinned Server PK)", ha="center", weight="bold", color="#1a365d")
    ax1.text(8, 9.3, "Server Node\n(Pinned Client PK)", ha="center", weight="bold", color="#742a2a")

    # Step 1: ClientHello
    ax1.annotate(
        "", xy=(7.9, 7.5), xytext=(2.1, 7.5),
        arrowprops=dict(arrowstyle="->", lw=2, color="#2563eb")
    )
    ax1.text(5, 7.8, "1. ClientHello {ver, suite, N_c, PK_kem_eph (1,184B), ts} [1,228 B]",
             ha="center", bbox=dict(boxstyle="round,pad=0.3", fc="#dbeafe", ec="#2563eb", lw=1.2))

    # Step 2: ServerHello
    ax1.annotate(
        "", xy=(2.1, 5.0), xytext=(7.9, 5.0),
        arrowprops=dict(arrowstyle="->", lw=2, color="#dc2626")
    )
    ax1.text(5, 5.3, "2. ServerHello {CT_kem (1,088B), N_s, ID_server, Sig_server (3,309B)} [4,449 B]",
             ha="center", bbox=dict(boxstyle="round,pad=0.3", fc="#fee2e2", ec="#dc2626", lw=1.2))

    # Step 3: ClientAuth
    ax1.annotate(
        "", xy=(7.9, 2.5), xytext=(2.1, 2.5),
        arrowprops=dict(arrowstyle="->", lw=2, color="#059669")
    )
    ax1.text(5, 2.8, "3. ClientAuth {ID_client, Sig_client (3,309B), MAC_confirm (32B)} [3,355 B]",
             ha="center", bbox=dict(boxstyle="round,pad=0.3", fc="#d1fae5", ec="#059669", lw=1.2))

    ax1.text(5, 1.2, "Channel Established (K_c2s, K_s2c derived via HKDF-SHA256 from SS)",
             ha="center", style="italic", weight="bold", color="#047857")

    # Bottom: Symmetric Binary Chunk Frame Layout
    ax2.set_xlim(0, 100)
    ax2.set_ylim(0, 10)
    ax2.axis("off")
    ax2.set_title("Binary Packet Layout (64 KB Authenticated Chunk)", weight="bold", pad=10)

    # Draw boxes
    boxes = [
        (0, 14, "Chunk Len (4B)\nuint32 BE", "#93c5fd"),
        (14, 20, "Counter (8B)\nMonotonic", "#bfdbfe"),
        (34, 18, "IV (12B)\nIV_base ^ Ctr", "#c7d2fe"),
        (52, 32, "Ciphertext (N Bytes)\nAES-256-GCM Payload", "#fed7aa"),
        (84, 16, "Tag (16B)\nAuth Tag", "#fca5a5"),
    ]

    for x, w, label, color in boxes:
        rect = patches.FancyBboxPatch((x, 2), w, 6, boxstyle="round,pad=0.2",
                                      fc=color, ec="#374151", lw=1.5)
        ax2.add_patch(rect)
        ax2.text(x + w / 2, 5, label, ha="center", va="center", fontsize=9, weight="bold")

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def plot_fig2_handshake_latency(summary_data: dict, output_path: str = "results/figures/fig2_handshake_latency.png"):
    """Figure 2: Handshake Latency Comparison across platforms with bootstrap error bars."""
    platforms = list(summary_data["platforms"].keys())
    means = [summary_data["platforms"][p]["handshake_latency_ms"]["mean"] for p in platforms]
    ci_lows = [summary_data["platforms"][p]["handshake_latency_ms"]["ci_95_lower"] for p in platforms]
    ci_highs = [summary_data["platforms"][p]["handshake_latency_ms"]["ci_95_upper"] for p in platforms]
    errors = [[m - l for m, l in zip(means, ci_lows)], [h - m for m, h in zip(means, ci_highs)]]

    labels = [p.replace("_", " ") for p in platforms]
    colors = ["#2563eb", "#ea580c", "#d97706", "#059669", "#7c3aed"][:len(platforms)]

    fig, ax = plt.subplots(figsize=(9, 5.5))
    bars = ax.bar(labels, means, yerr=errors, capsize=6, color=colors, edgecolor="#1f2937", lw=1.2, alpha=0.9)

    for bar, m in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5, f"{m:.2f} ms",
                ha="center", va="bottom", weight="bold", fontsize=10)

    ax.set_ylabel("1-RTT Handshake Latency (ms)", weight="bold")
    ax.set_title("Handshake Latency Across Platforms (with 95% Bootstrap CI)", weight="bold", pad=12)
    ax.grid(axis="y", linestyle="--", alpha=0.7)
    plt.xticks(rotation=15, ha="right")
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def plot_fig3_memory_footprint(summary_data: dict, output_path: str = "results/figures/fig3_memory_footprint.png"):
    """Figure 3: Peak RSS & Heap Allocation by Platform."""
    platforms = list(summary_data["platforms"].keys())
    labels = [p.replace("_", " ") for p in platforms]
    peak_rss = [summary_data["platforms"][p]["memory"]["peak_rss_mb"] for p in platforms]
    peak_heap = [summary_data["platforms"][p]["memory"]["peak_heap_mb"] for p in platforms]

    x = np.arange(len(platforms))
    width = 0.35

    fig, ax = plt.subplots(figsize=(9, 5.5))
    rects1 = ax.bar(x - width/2, peak_rss, width, label="Peak Process RSS (MB)", color="#3b82f6", edgecolor="#1e3a8a", lw=1.2)
    rects2 = ax.bar(x + width/2, peak_heap, width, label="Peak Python Heap (MB)", color="#10b981", edgecolor="#064e3b", lw=1.2)

    for r in rects1:
        ax.text(r.get_x() + r.get_width()/2, r.get_height() + 1, f"{r.get_height():.1f}", ha="center", va="bottom", fontsize=8)
    for r in rects2:
        ax.text(r.get_x() + r.get_width()/2, r.get_height() + 1, f"{r.get_height():.1f}", ha="center", va="bottom", fontsize=8)

    ax.set_ylabel("Memory Consumption (MB)", weight="bold")
    ax.set_title("Memory Profile: Peak RSS vs. Heap Across Platforms", weight="bold", pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha="right")
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.7)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def plot_fig4_wire_overhead(output_path: str = "results/figures/fig4_wire_overhead_pqc_vs_classical.png"):
    """Figure 4: PQC Handshake Wire Overhead vs. Classical ECDH/ECDSA Baseline."""
    categories = ["Client Public Key", "Ciphertext / Key Exch", "Server Identity / Signature", "Client Identity / Signature", "Total Handshake Bytes"]
    pqc_bytes = [1184, 1088, 3309 + 32, 3309 + 32, 1228 + 4449 + 3355]
    classical_bytes = [64, 64, 72, 72, 64 + 64 + 72 + 72 + 64]

    fig, ax = plt.subplots(figsize=(9, 5.5))
    x = np.arange(len(categories))
    width = 0.35

    r1 = ax.bar(x - width/2, pqc_bytes, width, label="QSC (ML-KEM-768 + ML-DSA-65)", color="#6366f1", edgecolor="#312e81")
    r2 = ax.bar(x + width/2, classical_bytes, width, label="Classical Reference (ECDH + ECDSA P-256)", color="#9ca3af", edgecolor="#374151")

    for bar, val in zip(r1, pqc_bytes):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 100, f"{val:,} B", ha="center", va="bottom", fontsize=8, weight="bold")
    for bar, val in zip(r2, classical_bytes):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 100, f"{val:,} B", ha="center", va="bottom", fontsize=8)

    ax.set_ylabel("Wire Size (Bytes, Log Scale)", weight="bold")
    ax.set_yscale("log")
    ax.set_title("Cryptographic Wire Overhead: Post-Quantum Bloat vs. Classical Baseline", weight="bold", pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(categories, rotation=15, ha="right")
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.7)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def plot_fig5_throughput(summary_data: dict, output_path: str = "results/figures/fig5_throughput_vs_payload.png"):
    """Figure 5: Throughput (MB/s) for 1 KB, 100 KB, and 10 MB files across platforms."""
    platforms = ["Platform_A", "Platform_B", "Platform_D"]
    available_platforms = [p for p in platforms if p in summary_data["platforms"]]
    payloads = ["1KB", "100KB", "10MB"]

    fig, ax = plt.subplots(figsize=(9, 5.5))
    x = np.arange(len(payloads))
    width = 0.25

    colors = ["#2563eb", "#ea580c", "#7c3aed"]
    for i, p in enumerate(available_platforms):
        tps = [summary_data["platforms"][p]["payloads"][pay]["throughput_mb_s"]["mean"] for pay in payloads]
        bars = ax.bar(x + (i - len(available_platforms)/2 + 0.5)*width, tps, width, label=p.replace("_", " "), color=colors[i], edgecolor="#111827")
        for b, val in zip(bars, tps):
            ax.text(b.get_x() + b.get_width()/2, b.get_height() + 2, f"{val:.1f}", ha="center", va="bottom", fontsize=8)

    ax.set_ylabel("Streaming AEAD Throughput (MB/s)", weight="bold")
    ax.set_title("Payload Streaming Throughput vs. File Size Across Platforms", weight="bold", pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(payloads)
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.7)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def plot_fig6_platform_d_tradeoff(summary_data: dict, output_path: str = "results/figures/fig6_platform_d_tradeoff.png"):
    """Figure 6: Platform D MTU Fragmentation & Wire Bloat Penalty Pareto Analysis."""
    p_a = summary_data["platforms"].get("Platform_A", {})
    p_d = summary_data["platforms"].get("Platform_D", {})

    lat_a = p_a.get("handshake_latency_ms", {}).get("mean", 5.0)
    lat_d = p_d.get("handshake_latency_ms", {}).get("mean", 35.0)

    fig, ax = plt.subplots(figsize=(9, 5.5))
    scenarios = ["Platform A (Baseline, Jumbo/Loopback MTU)", "Platform D (1500B Ethernet MTU + 15ms Jitter)"]
    latencies = [lat_a, lat_d]
    colors = ["#3b82f6", "#ef4444"]

    bars = ax.bar(scenarios, latencies, color=colors, width=0.5, edgecolor="#1f2937", lw=1.2)
    for b, val in zip(bars, latencies):
        ax.text(b.get_x() + b.get_width()/2, b.get_height() + 1, f"{val:.2f} ms", ha="center", va="bottom", weight="bold", fontsize=11)

    penalty = ((lat_d - lat_a) / max(0.001, lat_a)) * 100
    ax.annotate(
        f"+{penalty:.1f}% Latency Inflation\n(MTU fragmentation + TCP reassembly jitter)",
        xy=(1, lat_d), xytext=(0.5, lat_d * 0.75),
        arrowprops=dict(facecolor="black", shrink=0.05, width=1.5, headwidth=8),
        fontsize=10, weight="bold", bbox=dict(boxstyle="round,pad=0.4", fc="#fef3c7", ec="#f59e0b")
    )

    ax.set_ylabel("Handshake Latency (ms)", weight="bold")
    ax.set_title("Platform D Innovation: Post-Quantum Wire Bloat & MTU Fragmentation Impact", weight="bold", pad=12)
    ax.grid(axis="y", linestyle="--", alpha=0.7)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def generate_all_figures(summary_json_path: str = "results/tables/benchmark_summary.json"):
    fig_dir = Path("results/figures")
    fig_dir.mkdir(parents=True, exist_ok=True)

    with open(summary_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    print("Generating Figure 1: Handshake Wire Framing...")
    plot_fig1_wire_framing(str(fig_dir / "fig1_handshake_wire_framing.png"))

    print("Generating Figure 2: Handshake Latency...")
    plot_fig2_handshake_latency(data, str(fig_dir / "fig2_handshake_latency.png"))

    print("Generating Figure 3: Memory Footprint...")
    plot_fig3_memory_footprint(data, str(fig_dir / "fig3_memory_footprint.png"))

    print("Generating Figure 4: Wire Overhead PQC vs Classical...")
    plot_fig4_wire_overhead(str(fig_dir / "fig4_wire_overhead_pqc_vs_classical.png"))

    print("Generating Figure 5: Streaming Throughput vs Payload...")
    plot_fig5_throughput(data, str(fig_dir / "fig5_throughput_vs_payload.png"))

    print("Generating Figure 6: Platform D Trade-off Analysis...")
    plot_fig6_platform_d_tradeoff(data, str(fig_dir / "fig6_platform_d_tradeoff.png"))

    print("All 6 figures successfully saved to results/figures/.")


if __name__ == "__main__":
    generate_all_figures()
