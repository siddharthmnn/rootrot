# contributing to rootrot

thanks for taking a look at rootrot. this guide covers the local setup and the checks expected before opening a pull request.

## development environment

rootrot targets python 3.11 and newer. use a virtual environment so the project tools stay separate from your system python.

```bash
git clone https://github.com/siddharthmnn/rootrot.git
cd rootrot

python3.11 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

on windows powershell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

## day-to-day commands

```bash
make lint
make format-check
make test
make coverage
make build
make verify-dist
```

format the python files you changed before opening a pull request:

```bash
ruff format rootrot/path_to_changed_file.py tests/path_to_changed_test.py
```

the makefile's formatting target checks the new release-tooling files added in this milestone. older files are left untouched here to avoid mixing a repository-wide formatting diff into the infrastructure work.

the full local check is:

```bash
make check
```

these targets use ruff, unittest, coverage.py, build and twine. the project has no runtime third-party dependencies.

## tests

tests use the standard library `unittest` runner. add regression coverage for bug fixes and cover both the expected result and the relevant failure path when it makes sense.

```bash
python -m unittest discover -s tests -v
coverage run --branch -m unittest discover -s tests -v
coverage report
coverage html
```

the current coverage floor is 65%. raise it when the suite has enough meaningful coverage to justify a higher threshold; don't add tests that only exercise lines without checking behaviour.

## package build

build both supported distribution formats:

```bash
python -m build
python -m twine check dist/*
python scripts/verify_dist.py dist
```

the CI pipeline installs the wheel and source distribution into separate clean virtual environments and runs the console command from each installation.

## pull requests

- create a focused branch from the latest appropriate base branch.
- keep each change related to one piece of work.
- use lowercase, descriptive commit messages.
- run the relevant tests and checks before opening a pull request.
- describe the behaviour changed and the validation you actually ran.
- don't report a check as passing until it has completed successfully.

## project boundaries

rootrot is an isolated malware-behaviour simulation and detection lab. keep examples local and non-destructive. don't add real persistence, destructive file operations, network command-and-control, data exfiltration or code that modifies a host outside the temporary demo workspace.
