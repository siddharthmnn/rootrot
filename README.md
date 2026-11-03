# MALSTRIKE

**MALSTRIKE** is an isolated Python malware-behaviour simulation and detection lab for cybersecurity education. It demonstrates selected malware concepts through synthetic data and in-memory simulations, then correlates the resulting telemetry into detection findings.

> **Safety by design:** this project is not deployable malware. It does not access external networks, establish operating-system persistence, encrypt or delete files, collect credentials, execute arbitrary commands, or transmit data. Its file operations are restricted to a temporary workspace populated with synthetic training files.

## Features

- **File intelligence:** SHA-256 fingerprinting, metadata inspection, and Shannon entropy calculation.
- **Persistence indicators:** illustrates common persistence locations as events; it does not write to them.
- **C2 protocol simulation:** signed, allowlisted tasks exchanged through an in-memory queue, with no sockets or network transport.
- **Ransomware dry run:** identifies synthetic files by extension and reports what would be targeted; it never encrypts or changes them.
- **Data-staging simulation:** creates a chunk manifest containing sizes and hashes; no data is sent anywhere.
- **Behavioural detection:** correlates telemetry into rule-based findings.
- **Tamper-evident audit log:** links event records with SHA-256 hashes.
- **Automated tests:** covers path safety, event integrity, command allowlisting, and non-destructive behaviour.

## Requirements

- Python 3.10 or newer
- No third-party packages required

## Run

From the repository root, install the package in editable mode:

```bash
python -m pip install -e .
```

Run the complete lab:

```bash
python -m malstrike run
```

To save the JSON report:

```bash
python -m malstrike run --output reports/report.json
```

For a quick run without installing, use `PYTHONPATH=src python -m malstrike run` on Linux/WSL. On PowerShell, use `$env:PYTHONPATH="src"; python -m malstrike run`.

## Run tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Or use the Makefile:

```bash
make run
make test
```

## Repository layout

```text
malstrike-lab/
├── src/
│   └── malstrike/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── config.py
│       ├── detection.py
│       ├── events.py
│       ├── workspace.py
│       └── modules/
│           ├── __init__.py
│           ├── c2.py
│           ├── file_intel.py
│           ├── persistence.py
│           ├── ransomware.py
│           └── staging.py
├── tests/
│   ├── test_events.py
│   ├── test_simulation.py
│   └── test_workspace.py
├── .gitignore
├── Makefile
├── pyproject.toml
└── README.md
```

## Architecture

```text
                 MALSTRIKE CLI
                       |
                 Temporary Lab
                       |
      +----------------+----------------+
      |                |                |
  File Intel      Behaviour Sims    C2 Simulator
      |                |                |
      +----------------+----------------+
                       |
                 Event Logger
                 (hash chained)
                       |
                Detection Engine
                       |
                  JSON Report
```

## Learning objectives

1. Understand file fingerprinting and entropy as analysis signals.
2. Recognize persistence, beaconing, staging, and ransomware-like behaviours.
3. Understand authenticated task messages and command allowlisting.
4. Build event-based detection rules and correlate multiple indicators.
5. Validate audit-log integrity and write tests for safety invariants.

## Scope and limitations

The C2 component is an in-process protocol demonstration, not a remote-access tool. Persistence is represented by telemetry only. The ransomware component is read-only and does not implement file encryption. Staging produces metadata only and never performs exfiltration. These constraints are intentional so the project can be demonstrated safely in a classroom.

## Suggested extensions

- Add a Sigma-like YAML rule format for detection rules.
- Add timeline and severity summaries to the JSON report.
- Add more synthetic event sequences and unit tests.
- Add a MITRE ATT&CK mapping for the behaviours being simulated.
- Add a local dashboard that reads reports without executing samples.

## License

MIT. See `LICENSE`.
