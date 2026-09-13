# EndpointSweep — development shortcuts. Everything here is also a plain command.
.PHONY: help install test lint fmt fleet golden demo clean

help:
	@echo "install  editable install with dev extras"
	@echo "test     run the test suite (includes a live Linux collector run)"
	@echo "lint     ruff check"
	@echo "fmt      ruff check --fix"
	@echo "fleet    regenerate testdata/hosts/ (28 synthetic hosts)"
	@echo "golden   regenerate testdata/golden/ — then READ THE DIFF"
	@echo "demo     build out/fleet.{md,html,sarif} from the synthetic fleet"

install:
	pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check .

fmt:
	ruff check . --fix

fleet:
	python3 testdata/generate_fleet.py

golden:
	python3 testdata/generate_golden.py

demo:
	@mkdir -p out
	endpointsweep merge testdata/hosts -o out/fleet.json || true
	endpointsweep report out/fleet.json -o out/fleet.md || true
	endpointsweep report out/fleet.json -f html -o out/fleet.html || true
	endpointsweep report out/fleet.json -f sarif -o out/fleet.sarif || true
	@echo "wrote out/fleet.{json,md,html,sarif}"

clean:
	rm -rf out build dist *.egg-info .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
