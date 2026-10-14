"""Figures for PS-P1 (matplotlib only). Every figure is regenerated from results/tables/*.csv.

    python -m src.visualization          # draw everything that has data
"""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import networkx as nx  # noqa: E402
import pandas as pd  # noqa: E402

from .problem import COMPARISON_SETS, PARAMETER_SETS, RESULTS_FIGURES, RESULTS_TABLES  # noqa: E402
from .routing import PROCESSOR_C_STUDY, build_graph, load_processor  # noqa: E402

COLORS = {"classical-p256": "#6b7280", "pqc-L3": "#2563eb", "hybrid-L3": "#dc2626",
          "pqc-L1": "#60a5fa", "pqc-L5": "#1e3a8a"}
LABELS = {"classical-p256": "ECDH P-256", "pqc-L3": "ML-KEM-768", "hybrid-L3": "Hybrid ECDH+ML-KEM-768",
          "pqc-L1": "ML-KEM-512", "pqc-L5": "ML-KEM-1024"}


def _save(fig, name: str) -> Path:
    RESULTS_FIGURES.mkdir(parents=True, exist_ok=True)
    path = RESULTS_FIGURES / name
    fig.savefig(path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    return path


def _csv(name: str):
    p = RESULTS_TABLES / name
    return pd.read_csv(p) if p.exists() else None


import numpy as np

def _node_pos(g: nx.Graph, key: str, topology: str) -> dict:
    n = g.number_of_nodes()
    top_lower = str(topology).lower()
    if key == "A":
        if "ring" in top_lower or "cycle" in top_lower:
            return {i: (float(np.cos(2 * np.pi * i / n + np.pi / 2)), float(np.sin(2 * np.pi * i / n + np.pi / 2))) for i in range(n)}
        elif "chain" in top_lower:
            return {i: (float(i), 0.0) for i in range(n)}
        elif "star" in top_lower:
            pos = {0: (0.0, 0.0)}
            pos.update({i: (float(np.cos(2 * np.pi * (i - 1) / (n - 1))), float(np.sin(2 * np.pi * (i - 1) / (n - 1)))) for i in range(1, n)})
            return pos
        return nx.spring_layout(g, seed=42)
    elif key == "B":
        if "grid" in top_lower or "mesh" in top_lower:
            return {i: (float(i % 3), float(-(i // 3))) for i in range(n)}
        return nx.spring_layout(g, seed=42)
    return nx.spring_layout(g, seed=42)


def draw_processor(key: str) -> Path:
    proc = load_processor(key)
    g = build_graph(proc["coupling_map"], proc["num_qubits"])
    pos = _node_pos(g, key, proc.get("topology", ""))
    fig, ax = plt.subplots(figsize=(6, 4.2))
    nx.draw(g, pos, with_labels=True, node_size=900, node_color="#dbeafe", edgecolors="#1e3a8a",
            font_weight="bold", ax=ax)
    ax.set_title(f"{proc['name']}: {proc['num_qubits']} qubits, {proc['topology']}\n"
                 f"edges: {', '.join(f'{a}-{b}' for a, b in proc['coupling_map'])}", fontsize=10)
    return _save(fig, f"processor_{key}_graph.png")


def draw_processor_c_study() -> Path:
    g = build_graph(PROCESSOR_C_STUDY, 13)
    pos = nx.circular_layout(g.subgraph(range(12)))
    pos[12] = (0, 0)
    fig, ax = plt.subplots(figsize=(5, 5))
    nx.draw(g, pos, with_labels=True, node_size=500, node_color="#f3f4f6", edgecolors="#6b7280", ax=ax)
    ax.set_title("Processor C (13 qubits) - study/reference only", fontsize=10)
    return _save(fig, "processor_C_study_graph.png")


# ---------------------------------------------------------------- handshake flow
def draw_handshake_flow() -> Path:
    fig, ax = plt.subplots(figsize=(10, 6.6))
    ax.set_xlim(0, 10); ax.set_ylim(0, 10); ax.axis("off")
    ax.text(2, 9.6, "Client", ha="center", fontsize=13, weight="bold")
    ax.text(8, 9.6, "Server", ha="center", fontsize=13, weight="bold")
    for x in (2, 8):
        ax.plot([x, x], [0.3, 9.2], color="#9ca3af", lw=1.5)
    steps = [
        (8.6, "R", "ClientHello: nonce_c, KEM public key (ephemeral),\nalgorithm names + Sig_C (ML-DSA)", "#2563eb"),
        (7.0, "L", "ServerHello: nonce_s, KEM ciphertext\n+ Sig_S over H(ClientHello || ServerHello)", "#2563eb"),
        (5.6, "L", "Finished (AES-256-GCM record, key confirmation)", "#059669"),
        (4.7, "R", "Finished (AES-256-GCM record, key confirmation)", "#059669"),
        (3.5, "R", "Application data: AES-256-GCM records (chunked / streamed,\nsequence number + final flag authenticated)", "#7c3aed"),
    ]
    for y, d, text, c in steps:
        x0, x1 = (2, 8) if d == "R" else (8, 2)
        ax.annotate("", xy=(x1, y), xytext=(x0, y), arrowprops=dict(arrowstyle="->", color=c, lw=2))
        ax.text(5, y + 0.12, text, ha="center", va="bottom", fontsize=9, color=c)
    box = dict(facecolor="white", edgecolor="none", pad=3)
    ax.text(2, 1.9, "verify Sig_S (pinned server key)\nKEM decapsulate -> shared secret", ha="center", fontsize=8.5, bbox=box)
    ax.text(8, 1.9, "verify Sig_C (pinned client key)\nKEM encapsulate -> shared secret", ha="center", fontsize=8.5, bbox=box)
    ax.text(5, 0.6, "Both: HKDF-SHA256(secret, salt = nonce_c||nonce_s, info = transcript hash) -> two AES-256 keys\n"
                    "MITM cannot swap the KEM key/ciphertext without breaking a signature; any record change breaks the GCM tag.",
            ha="center", fontsize=8.5, style="italic", bbox=box)
    ax.set_title("PS-P1 handshake flow (mutual ML-DSA authentication, ML-KEM key establishment)", fontsize=11)
    return _save(fig, "handshake_flow.png")


# ---------------------------------------------------------------- benchmark figures
def fig_headline() -> Path | None:
    df = _csv("headline_comparison.csv")
    if df is None or df.empty:
        return None
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.2))
    envs = list(dict.fromkeys(df.environment))
    sets = [s for s in COMPARISON_SETS if s in set(df.param_set)]
    w = 0.8 / max(1, len(sets))
    for ax, col, title, unit in [(axes[0], "handshake_ms_median", "Handshake time (median)", "ms"),
                                 (axes[1], "handshake_bytes_on_wire", "Handshake bytes on the wire", "bytes"),
                                 (axes[2], "ram_heap_peak_kb_10MB", "RAM (Python heap peak, 10 MB transfer)", "KB")]:
        for i, s in enumerate(sets):
            vals = [df[(df.environment == e) & (df.param_set == s)][col].iloc[0] for e in envs]
            ax.bar([x + i * w for x in range(len(envs))], vals, w, label=LABELS[s], color=COLORS[s])
        ax.set_xticks([x + w * (len(sets) - 1) / 2 for x in range(len(envs))]); ax.set_xticklabels(envs)
        ax.set_title(title); ax.set_ylabel(unit); ax.grid(axis="y", alpha=0.3)
    axes[2].set_yscale("log")
    axes[0].legend(fontsize=8)
    fig.suptitle("Laptop vs edge device: classical ECDH P-256 vs PQC / hybrid", fontsize=12)
    return _save(fig, "headline_laptop_vs_edge.png")


def fig_sizes() -> Path | None:
    df = _csv("primitive_sizes_and_ops.csv")
    if df is None or df.empty:
        return None
    cols = [("kem_public_key_B", "KEM public key"), ("kem_ciphertext_B", "KEM ciphertext"),
            ("sig_public_key_B", "Signature public key"), ("signature_B", "Signature")]
    fig, ax = plt.subplots(figsize=(10, 4.5))
    w = 0.8 / len(df)
    for i, r in enumerate(df.itertuples()):
        ax.bar([x + i * w for x in range(len(cols))], [getattr(r, c) for c, _ in cols], w,
               label=LABELS.get(r.param_set, r.param_set), color=COLORS.get(r.param_set))
    ax.set_xticks([x + w * (len(df) - 1) / 2 for x in range(len(cols))]); ax.set_xticklabels([n for _, n in cols])
    ax.set_yscale("log"); ax.set_ylabel("bytes (log scale)"); ax.grid(axis="y", alpha=0.3); ax.legend(fontsize=8)
    ax.set_title("Key, ciphertext and signature sizes (measured)")
    return _save(fig, "sizes_comparison.png")


def fig_transfer() -> Path | None:
    df = _csv("pqc_benchmark.csv")
    if df is None or df.empty:
        return None
    df = df[df.backend == df.backend.iloc[0]] if df.backend.nunique() == 1 else df[df.backend == "classical-p256"]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    for plat, sub in df.groupby("platform"):
        sub = sub.sort_values("payload_bytes")
        ax.plot(sub.payload_bytes, sub.transfer_ms_median, marker="o", label=f"Platform {plat}")
    ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("payload bytes"); ax.set_ylabel("transfer time (ms, median)")
    ax.grid(alpha=0.3); ax.legend(); ax.set_title("AES-256-GCM transfer time by platform (record layer is KEM-independent)")
    return _save(fig, "transfer_by_platform.png")


def fig_memory() -> Path | None:
    df = _csv("pqc_benchmark.csv")
    if df is None or df.empty:
        return None
    sub = df[(df.instance_id == "10MB") & (df.backend == df.backend.iloc[0])]
    fig, ax = plt.subplots(figsize=(7, 4.2))
    labels = [f"{p}\n({'1 record' if str(c) == 'single-record' else f'{int(c) // 1024} KiB records'})"
              for p, c in zip(sub.platform, sub.chunk_bytes)]
    ax.bar(labels, sub.tracemalloc_peak_kb / 1024, color="#2563eb")
    for i, b in enumerate(sub.mem_budget_mb):
        if str(b) != "none":
            ax.hlines(float(b), i - 0.4, i + 0.4, colors="#dc2626", linestyles="--")
    ax.set_yscale("log"); ax.set_ylabel("Python-heap peak (MB, log); red dash = platform budget")
    ax.grid(axis="y", alpha=0.3); ax.set_title("RAM needed to move a 10 MB payload")
    return _save(fig, "memory_by_platform.png")


def fig_chunk_sweep() -> Path | None:
    df = _csv("chunk_sweep.csv")
    if df is None or df.empty:
        return None
    d = df[df.chunk_bytes != "single-record"].copy()
    d["chunk_bytes"] = d.chunk_bytes.astype(int)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.plot(d.chunk_bytes / 1024, d.throughput_MBps, "o-", color="#2563eb", label="throughput (MB/s)")
    ax.set_xscale("log", base=2); ax.set_xlabel("record size (KiB)"); ax.set_ylabel("throughput (MB/s)", color="#2563eb")
    ax2 = ax.twinx()
    ax2.plot(d.chunk_bytes / 1024, d.tracemalloc_peak_kb / 1024, "s--", color="#dc2626")
    ax2.set_ylabel("heap peak (MB)", color="#dc2626"); ax2.set_yscale("log")
    ax.grid(alpha=0.3); ax.set_title("Record-size trade-off used to design Platform D")
    return _save(fig, "chunk_sweep.png")


def fig_routing() -> Path | None:
    df = _csv("routing_estimate.csv")
    if df is None or df.empty:
        return None
    df = df[df.processor.isin(("Processor A", "Processor B"))]
    if df.empty:
        return None
    piv = df.pivot(index="workload", columns="processor", values="swaps_estimate")
    ax = piv.plot.bar(figsize=(9, 4.5), color=["#2563eb", "#dc2626"], rot=15)
    ax.set_ylabel("estimated SWAPs"); ax.set_title("Illustrative routing estimate on required A/B maps (identity layout)")
    ax.grid(axis="y", alpha=0.3)
    return _save(ax.get_figure(), "routing_estimate_AB.png")


def make_all() -> list[str]:
    made = [draw_processor("A"), draw_processor("B"), draw_processor_c_study(), draw_handshake_flow()]
    for fn in (fig_headline, fig_sizes, fig_transfer, fig_memory, fig_chunk_sweep, fig_routing):
        r = fn()
        if r is not None:
            made.append(r)
    return [str(p.name) for p in made]


if __name__ == "__main__":
    print("\n".join(make_all()))
