PYTHON ?= python

.PHONY: help install-dev lint format format-check test coverage validate replay benchmark build verify-dist check clean

help:
	@echo "install-dev  install rootrot and development tools"
	@echo "lint         run ruff checks"
	@echo "format       format python files with ruff"
	@echo "format-check check formatting without changing files"
	@echo "test         run the unittest suite"
	@echo "coverage     run tests and enforce the coverage floor"
	@echo "validate     run synthetic detection and parser validation"
	@echo "replay       replay the multi-stage validation scenario"
	@echo "benchmark    benchmark detection and telemetry operations"
	@echo "build        build wheel and source distribution"
	@echo "verify-dist  inspect distribution contents"
	@echo "check        run the full local quality check"
	@echo "clean        remove generated files"

install-dev:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	ruff check .

format:
	ruff format scripts/verify_dist.py tests/test_project_metadata.py

format-check:
	ruff format --check scripts/verify_dist.py tests/test_project_metadata.py

test:
	$(PYTHON) -m unittest discover -s tests -v

coverage:
	coverage run --branch -m unittest discover -s tests -v
	coverage report --fail-under=65
	coverage html

validate:
	$(PYTHON) -m rootrot validate

replay:
	$(PYTHON) -m rootrot replay --scenario multi_stage_chain --repeat 3

benchmark:
	$(PYTHON) -m rootrot benchmark --sizes 100,1000,10000 --iterations 3

build:
	rm -rf build dist
	$(PYTHON) -m build

verify-dist:
	$(PYTHON) -m twine check dist/*
	$(PYTHON) scripts/verify_dist.py dist

check: lint format-check coverage build verify-dist

clean:
	rm -rf build dist rootrot.egg-info .coverage coverage.xml htmlcov .ruff_cache
