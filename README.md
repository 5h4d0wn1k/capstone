# Capstone SIEM — Real-Time Security Event Management

Academic capstone implementation of a **Security Information and Event
Management (SIEM)** system with **machine-learning anomaly detection**,
multi-source collectors, YARA/Sigma detection rules, network monitoring, and a
real-time dashboard (Python, asyncio, Socket.IO).

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/capstone)](https://github.com/5h4d0wn1k/capstone)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/capstone)](https://github.com/5h4d0wn1k/capstone/issues)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/capstone)](https://github.com/5h4d0wn1k/capstone)

## Why

SIEM platforms sit at the center of every modern security operations center,
yet the concepts behind them — pipelining logs through collectors, normalizers,
correlation rules, and detection engines — are often hidden inside expensive
commercial products. This capstone project surfaces those concepts in a
practical, academic-grade system: an asyncio event pipeline that ingests events,
applies rule-based and **Isolation-Forest-based anomaly detection**, computes a
live threat level, and streams everything to a real-time web dashboard over
Socket.IO. It demonstrates the full detection stack — collectors (Windows,
Syslog, custom), YARA and Sigma detectors, event correlation, network flow
analysis, and incident-response scaffolding — in one codebase, and is designed
to be run and studied in a controlled lab environment on systems you own.

## Features

- **Real-time event pipeline** — asyncio + Socket.IO backed ingestion and streaming
- **ML anomaly detection** — scikit-learn **Isolation Forest** on normalized event features
- **Threshold-based detectors** — rule-driven alerts and severity classification
- **Multi-source collectors** — Windows event, syslog, and custom log collectors
- **YARA & Sigma detection** — signature and correlation rule engines
- **Network monitoring** — packet capture, flow analysis, and protocol analysis modules
- **Live dashboard** — event timeline, alert distribution, health indicators, threat level (`http://localhost:8080`)
- **Incident-response scaffolding** — response actions, playbook engine, and case management modules
- **Persistent storage** — SQLAlchemy async (SQLite `siem.db`) with event/alert/network models

## Quickstart

Requirements: Python 3.x. Dependencies in `requirements.txt` (includes
`aiohttp`, `python-socketio`, `sqlalchemy`, `scikit-learn`, `numpy`, `loguru`,
`aiohttp-jinja2`, `cryptography`, `psutil`).

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Set the secret key
export SIEM_SECRET_KEY=your-secret-key     # Windows: set SIEM_SECRET_KEY=...

# Start the SIEM + dashboard
python main.py

# Open the dashboard
open http://localhost:8080

# Monitor the log stream
tail -f siem.log
```

Configuration lives in `config.yaml` (system, monitoring, security, and ML
settings) with additional files under `config/` (`siem_config.yaml`,
`test_config.yaml`, Prometheus examples).

## Testing

Run the pytest suite (async-mode configured in `pytest.ini`):

```bash
python -m pytest
```

or `python -m pytest tests` for the event-collection tests (`test_events.py`).

## Project structure

- `main.py` — asyncio application entry point (HTTP + WebSocket)
- `models.py` — Event/Alert/NetworkLog DB models
- `modules/` — capability tree: `collectors/`, `analyzers/`, `detectors/`
  (YARA/Sigma/anomaly/ML), `monitors/`, `network/`, `defensive/`, `offensive/`
- `web/` — API and dashboard plumbing (`app.py`, `alerts.py`, `auth.py`, `monitors.py`)
- `config/` — YAML configuration, rule, and playbook directories
- `static/` `templates/` — dashboard UI

## Authorized use

This project is an educational capstone. Use it only for learning, coursework,
and lab experiments on systems you own or are explicitly authorized to assess.
Handle collected data responsibly and follow applicable laws and your
institution's policies.

## Contributing

Contributions welcome: fork, create a feature branch, and submit a pull request.

## License

Apache License 2.0 — see [LICENSE](LICENSE).