"""Supplemental Qiskit architecture probe for the Phase 1 Processor A/B maps.

PS-P1's ML-KEM/ML-DSA secure channel is classical software. This small GHZ-5
experiment is kept separate: it demonstrates transpilation and the kit's fixed
noise model on the required coupling maps, without claiming that PQC runs on a
quantum processor.
"""
from __future__ import annotations

import csv
import json
import math
from pathlib import Path

from .problem import PROCESSORS_DIR, RESULTS_FIGURES, RESULTS_TABLES

BASIS_GATES = ["rz", "sx", "x", "cx"]
SHOTS = 4096
SEED = 42
NOISE = {
    "single_qubit_depolarizing": 0.001,
    "cx_depolarizing": 0.005,
    "readout_bitflip": 0.01,
}


def ghz5_circuit():
    """Return the same measured star-GHZ circuit for both processor models."""
    from qiskit import QuantumCircuit

    qc = QuantumCircuit(5, 5, name="STAR-GHZ-5")
    qc.h(0)
    for q in range(1, 5):
        qc.cx(0, q)
    qc.measure(range(5), range(5))
    return qc


def _coupling_map(key: str):
    from qiskit.transpiler import CouplingMap

    data = json.loads((Path(PROCESSORS_DIR) / f"processor_{key}.json").read_text(encoding="utf-8"))
    edges = data["coupling_map"]
    directed = edges + [[b, a] for a, b in edges]
    return data, CouplingMap(couplinglist=directed)


def _noise_model():
    from qiskit_aer.noise import NoiseModel, ReadoutError, depolarizing_error

    model = NoiseModel(basis_gates=BASIS_GATES)
    model.add_all_qubit_quantum_error(
        depolarizing_error(NOISE["single_qubit_depolarizing"], 1), ["rz", "sx", "x"]
    )
    model.add_all_qubit_quantum_error(depolarizing_error(NOISE["cx_depolarizing"], 2), ["cx"])
    p = NOISE["readout_bitflip"]
    model.add_all_qubit_readout_error(ReadoutError([[1 - p, p], [p, 1 - p]]))
    return model


def _success_probability(counts: dict[str, int], shots: int) -> float:
    clean = {key.replace(" ", ""): value for key, value in counts.items()}
    successes = clean.get("00000", 0) + clean.get("11111", 0)
    return successes / shots


def _svg(rows: list[dict]) -> str:
    width, height = 720, 380
    left, top, chart_w, chart_h = 90, 45, 560, 240
    colors = {"ideal": "#4878a8", "noisy": "#d9822b"}
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="360" y="26" text-anchor="middle" font-family="Arial" font-size="18">GHZ-5 success rate (4096 shots)</text>',
    ]
    for tick in range(0, 6):
        value = tick / 5
        y = top + chart_h * (1 - value)
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left + chart_w}" y2="{y:.1f}" stroke="#ddd"/>')
        parts.append(f'<text x="{left - 12}" y="{y + 4:.1f}" text-anchor="end" font-family="Arial" font-size="12">{value:.1f}</text>')
    group_w = chart_w / max(1, len(rows))
    bar_w = 54
    for index, row in enumerate(rows):
        center = left + group_w * (index + 0.5)
        for offset, label, key in [(-bar_w / 2 - 3, "ideal", "p_success_ideal"), (3, "noisy", "p_success_noisy")]:
            val = float(row[key])
            h = chart_h * val
            x = center + offset
            y = top + chart_h - h
            parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{h:.1f}" fill="{colors[label]}"/>')
            parts.append(f'<text x="{x + bar_w / 2:.1f}" y="{y - 5:.1f}" text-anchor="middle" font-family="Arial" font-size="11">{val:.3f}</text>')
        parts.append(f'<text x="{center:.1f}" y="{top + chart_h + 24}" text-anchor="middle" font-family="Arial" font-size="14">Processor {row["processor"]}</text>')
        parts.append(f'<text x="{center:.1f}" y="{top + chart_h + 43}" text-anchor="middle" font-family="Arial" font-size="11">SWAPs: {row["swap_count"]}</text>')
    parts += [
        '<rect x="235" y="340" width="14" height="14" fill="#4878a8"/><text x="255" y="352" font-family="Arial" font-size="12">Ideal</text>',
        '<rect x="330" y="340" width="14" height="14" fill="#d9822b"/><text x="350" y="352" font-family="Arial" font-size="12">Fixed-noise model</text>',
        '<text x="18" y="170" transform="rotate(-90 18 170)" text-anchor="middle" font-family="Arial" font-size="13">Success probability</text>',
        '</svg>',
    ]
    return "\n".join(parts)


def run_probe(shots: int = SHOTS, seed: int = SEED) -> list[dict]:
    """Transpile and simulate the same GHZ circuit on A and B; save reproducible artifacts."""
    from qiskit import __version__ as qiskit_version, transpile
    from qiskit_aer import AerSimulator, __version__ as aer_version

    logical = ghz5_circuit()
    noise_model = _noise_model()
    rows: list[dict] = []
    circuit_text = ["Logical circuit (same input on A and B):", str(logical)]
    for key in ("A", "B"):
        processor, cmap = _coupling_map(key)
        compiled = transpile(
            logical,
            coupling_map=cmap,
            basis_gates=BASIS_GATES,
            optimization_level=1,
            layout_method="sabre",
            routing_method="sabre",
            seed_transpiler=seed,
        )
        routed = transpile(
            logical,
            coupling_map=cmap,
            basis_gates=BASIS_GATES + ["swap"],
            optimization_level=1,
            layout_method="sabre",
            routing_method="sabre",
            seed_transpiler=seed,
        )
        ideal_counts = AerSimulator(seed_simulator=seed).run(compiled, shots=shots).result().get_counts()
        noisy_counts = AerSimulator(noise_model=noise_model, seed_simulator=seed).run(compiled, shots=shots).result().get_counts()
        p_ideal = _success_probability(ideal_counts, shots)
        p_noisy = _success_probability(noisy_counts, shots)
        active = {compiled.find_bit(q).index for inst in compiled.data for q in inst.qubits}
        rows.append({
            "processor": key,
            "processor_name": processor["name"],
            "logical_qubits": logical.num_qubits,
            "physical_qubits_available": processor["num_qubits"],
            "physical_qubits_used": len(active),
            "cx_count": int(compiled.count_ops().get("cx", 0)),
            "depth": int(compiled.depth()),
            "swap_count": int(routed.count_ops().get("swap", 0)),
            "shots": shots,
            "p_success_ideal": p_ideal,
            "p_success_noisy": p_noisy,
            "noisy_standard_error": math.sqrt(p_noisy * (1 - p_noisy) / shots),
            "seed_transpiler": seed,
            "seed_simulator": seed,
        })
        circuit_text.extend([f"\nProcessor {key} transpiled circuit:", str(compiled)])

    RESULTS_TABLES.mkdir(parents=True, exist_ok=True)
    RESULTS_FIGURES.mkdir(parents=True, exist_ok=True)
    with (RESULTS_TABLES / "architecture_probe.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    metadata = {
        "experiment": "supplemental star-GHZ-5 architecture probe",
        "scope": "Qiskit processor-architecture study; not a quantum execution of the classical PS-P1 PQC channel",
        "qiskit_version": qiskit_version,
        "qiskit_aer_version": aer_version,
        "shots": shots,
        "seed": seed,
        "transpilation": {"basis_gates": BASIS_GATES, "optimization_level": 1, "layout_method": "sabre", "routing_method": "sabre"},
        "noise": NOISE,
        "processors": rows,
        "logical_circuit": str(logical),
    }
    (RESULTS_TABLES / "architecture_probe_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (RESULTS_TABLES / "architecture_probe_circuits.txt").write_text("\n".join(circuit_text) + "\n", encoding="utf-8")
    (RESULTS_FIGURES / "architecture_probe.svg").write_text(_svg(rows), encoding="utf-8")
    return rows


if __name__ == "__main__":
    for result in run_probe():
        print(json.dumps(result))
