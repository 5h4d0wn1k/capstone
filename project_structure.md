# SIEM Project Structure

```
capstone/
├── config/
│   ├── config.yaml           # Main configuration
│   ├── rules/               # Detection rules
│   │   ├── yara/           # YARA rules
│   │   ├── sigma/          # Sigma rules
│   │   └── correlation/    # Event correlation rules
│   └── playbooks/          # Incident response playbooks
├── modules/
│   ├── collectors/         # Log collectors
│   │   ├── windows.py     # Windows event collector
│   │   ├── syslog.py      # Syslog collector
│   │   └── custom.py      # Custom log collector
│   ├── analyzers/         # Log analysis
│   │   ├── parser.py      # Log parser
│   │   ├── normalizer.py  # Log normalizer
│   │   └── correlator.py  # Event correlator
│   ├── detectors/         # Threat detection
│   │   ├── yara_scan.py   # YARA scanner
│   │   ├── sigma_scan.py  # Sigma scanner
│   │   └── ml_detect.py   # ML-based detection
│   ├── network/           # Network monitoring
│   │   ├── packet_capture.py
│   │   ├── flow_analyzer.py
│   │   └── protocol_analyzer.py
│   ├── response/          # Incident response
│   │   ├── actions.py     # Response actions
│   │   ├── playbooks.py   # Playbook engine
│   │   └── cases.py       # Case management
│   └── reporting/         # Reporting
│       ├── metrics.py     # Metrics collection
│       ├── visualizer.py  # Data visualization
│       └── reports.py     # Report generation
├── web/                   # Web interface
│   ├── static/
│   │   ├── css/
│   │   ├── js/
│   │   └── img/
│   └── templates/
│       ├── dashboard.html
│       ├── alerts.html
│       └── reports.html
├── data/                  # Data storage
│   ├── logs/             # Log files
│   ├── alerts/           # Alert data
│   └── reports/          # Generated reports
├── tests/                # Unit tests
├── docs/                 # Documentation
├── requirements.txt      # Python dependencies
└── README.md            # Project documentation
```
