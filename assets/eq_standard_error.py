"""Standard error, general and for <ZZ>.

Run from anywhere:  python eq_standard_error.py
Writes eq_standard_error.png next to this script. Needs only matplotlib.
"""
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams.update({"mathtext.fontset": "cm", "font.family": "serif"})

OUT = Path(__file__).resolve().parent / "eq_standard_error.png"
EQUATION = r"""$\mathrm{SE} = \dfrac{\sigma}{\sqrt{N}},\qquad \mathrm{SE}_{\langle ZZ\rangle} = \sqrt{\dfrac{1 - \langle ZZ \rangle^{2}}{N}}$"""

fig = plt.figure(figsize=(0.1, 0.1))
fig.patch.set_facecolor("white")
fig.text(0, 0, EQUATION, fontsize=26, color="black")
fig.savefig(OUT, dpi=300, bbox_inches="tight", pad_inches=0.12, facecolor="white")
plt.close(fig)
print("wrote", OUT)
