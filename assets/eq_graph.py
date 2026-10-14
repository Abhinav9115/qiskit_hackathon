"""Coupling graph, average shortest path and diameter.

Run from anywhere:  python eq_graph.py
Writes eq_graph.png next to this script. Needs only matplotlib.
"""
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams.update({"mathtext.fontset": "cm", "font.family": "serif"})

OUT = Path(__file__).resolve().parent / "eq_graph.png"
EQUATION = r"""$G = (V, E),\qquad \bar{d} = \dfrac{2}{n(n-1)}\sum_{i<j} d(i,j),\qquad \mathrm{diam}(G) = \max_{i,j}\, d(i,j)$"""

fig = plt.figure(figsize=(0.1, 0.1))
fig.patch.set_facecolor("white")
fig.text(0, 0, EQUATION, fontsize=26, color="black")
fig.savefig(OUT, dpi=300, bbox_inches="tight", pad_inches=0.12, facecolor="white")
plt.close(fig)
print("wrote", OUT)
