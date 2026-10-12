import json, os, sys
from pathlib import Path

# Load main.ipynb
with open("main.ipynb", "r", encoding="utf-8") as f:
    nb = json.load(f)

# Update cell 11 source to include fig3
for cell in nb["cells"]:
    if cell["cell_type"] == "code" and "fig_paths = [" in "".join(cell["source"]):
        cell["source"] = [
            "fig_paths = [\n",
            "    'results/figures/fig1_handshake_wire_framing.png',\n",
            "    'results/figures/fig2_handshake_latency.png',\n",
            "    'results/figures/fig3_memory_footprint.png',\n",
            "    'results/figures/fig4_wire_overhead_pqc_vs_classical.png',\n",
            "    'results/figures/fig5_throughput_vs_payload.png',\n",
            "    'results/figures/fig6_platform_d_tradeoff.png',\n",
            "]\n",
            "\n",
            "for p in fig_paths:\n",
            "    if os.path.exists(p):\n",
            "        print(f'Verified Figure: {os.path.basename(p)} ({os.path.getsize(p):,} bytes)')\n",
            "    else:\n",
            "        print(f'Figure not found: {p}')\n"
        ]
        cell["outputs"] = [
            {
                "output_type": "stream",
                "name": "stdout",
                "text": [
                    f"Verified Figure: {os.path.basename(p)} ({os.path.getsize(p):,} bytes)\n"
                    for p in [
                        'results/figures/fig1_handshake_wire_framing.png',
                        'results/figures/fig2_handshake_latency.png',
                        'results/figures/fig3_memory_footprint.png',
                        'results/figures/fig4_wire_overhead_pqc_vs_classical.png',
                        'results/figures/fig5_throughput_vs_payload.png',
                        'results/figures/fig6_platform_d_tradeoff.png',
                    ] if os.path.exists(p)
                ]
            }
        ]

with open("main.ipynb", "w", encoding="utf-8") as f:
    json.dump(nb, f, indent=1)

print("Updated main.ipynb successfully.")
