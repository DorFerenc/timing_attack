timing-attack-project/
├── README.md
├── requirements.txt
├── Dockerfile
├── .dockerignore
├── .gitignore
├── config/
│   └── config.yaml
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── interfaces.py      # Abstract interfaces (SOLID: D)
│   │   ├── models.py           # Data models
│   │   └── exceptions.py       # Custom exceptions
│   ├── services/
│   │   ├── __init__.py
│   │   ├── timing_service.py   # Timing measurements (SOLID: S)
│   │   ├── http_service.py     # HTTP communications (SOLID: S)
│   │   └── analysis_service.py # Statistical analysis (SOLID: S)
│   ├── attack/
│   │   ├── __init__.py
│   │   └── timing_attacker.py  # Main attack orchestrator
│   └── utils/
│       ├── __init__.py
│       ├── logger.py
│       └── stats.py
└── tests/
    ├── __init__.py
    └── test_timing_attacker.py