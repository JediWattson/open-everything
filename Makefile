VENV := .venv
PY   := $(VENV)/bin/python
OE   := $(VENV)/bin/oe

.DEFAULT_GOAL := help
.PHONY: help setup setup-model check test doctor smoke clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

setup: ## Full setup: venv, Python deps, JDK, Ghidra
	./setup.sh

setup-model: ## setup + pre-download the embedding model (~3 GB)
	./setup.sh --with-model

check: ## Verify the environment without installing anything
	./setup.sh --check

global: ## Symlink oe into ~/.local/bin so it runs from anywhere
	mkdir -p ~/.local/bin
	ln -sf $(abspath $(OE)) ~/.local/bin/oe
	@echo "oe -> ~/.local/bin/oe"

test: ## Unit tests (no Ghidra or model needed)
	$(PY) -m pytest tests/ -q

doctor: ## oe doctor — environment report
	$(OE) doctor

smoke: ## Ingest /bin/ls and search it (first run downloads the model)
	$(OE) ingest /bin/ls
	$(OE) search "print file size" -k 5

clean: ## Remove .venv, cmake build dir, and caches
	rm -rf $(VENV) build *.egg-info src/*.egg-info
	find . -type d \( -name __pycache__ -o -name .pytest_cache \) -prune -exec rm -rf {} +
