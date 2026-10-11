.PHONY: install test demo bench figures clean help

PYTHON ?= python3

help:
	@echo "Quantum-Safe Channel (QSC) — Build & Execution Targets:"
	@echo "  make install   Install dependencies"
	@echo "  make test      Run unit, tamper, replay, and security test suite"
	@echo "  make demo      Run automated end-to-end demo and MitM attack rejection"
	@echo "  make bench     Execute multi-platform benchmarks (Platforms A, B, D)"
	@echo "  make figures   Generate publication-grade figures in results/figures/"
	@echo "  make clean     Clean caches and temporary outputs"

install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	$(PYTHON) -m pytest -v tests/

demo:
	$(PYTHON) -m src.cli attack-demo

bench:
	$(PYTHON) -m src.benchmark
	$(PYTHON) -m src.visualization

figures:
	$(PYTHON) -m src.visualization

clean:
	rm -rf .pytest_cache __pycache__ src/__pycache__ tests/__pycache__ optional/__pycache__
	rm -rf results/scratch_trust results/attack_trust
