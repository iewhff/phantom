# AI-Enhanced Pentesting Framework

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

An AI-powered penetration testing framework that combines automated security scanning with LLM-based analysis for intelligent vulnerability detection and reporting.

## Features

- 🔍 **Automated Reconnaissance**: Subdomain enumeration, port scanning, technology detection
- 🛡️ **Vulnerability Scanning**: Integration with Nuclei, custom checks for headers, SSL, CORS
- 🤖 **AI-Powered Analysis**: False positive filtering, exploit chain detection, severity prioritization
- 📊 **Professional Reports**: PDF, HTML, JSON, and Markdown output formats
- 🔗 **Exploit Chain Detection**: AI-identified attack paths combining multiple vulnerabilities
- 💾 **State Management**: Save/resume scans, checkpoint support
- 🔐 **Secure Storage**: Encrypted credentials and findings

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CLI Interface                            │
├─────────────────────────────────────────────────────────────┤
│                    Orchestrator                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
│  │  Recon   │→│ Scanning │→│ AI Engine│→│  Reporting   │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   │
│  │ Rate Limiter│ │State Manager│ │  Knowledge Base     │   │
│  └─────────────┘ └─────────────┘ └─────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   │
│  │   Ollama    │ │   ChromaDB  │ │     SQLite DB       │   │
│  └─────────────┘ └─────────────┘ └─────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.11+
- [Ollama](https://ollama.ai) for local LLM inference
- External tools: Nuclei, Nmap, Subfinder (optional)

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/ai-pentest.git
cd ai-pentest

# Run setup script
chmod +x scripts/setup.sh
./scripts/setup.sh

# Or manual installation
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Install External Tools

```bash
chmod +x scripts/install_tools.sh
./scripts/install_tools.sh
```

### Docker Setup

```bash
# Start all services
docker-compose up -d

# Run a scan
docker-compose run pentest scan example.com
```

## Usage

### Basic Scan

```bash
# Scan a domain
pentest scan example.com

# Scan with specific output format
pentest scan example.com -f html

# Scan without AI analysis
pentest scan example.com --no-ai

# Scan with additional scope
pentest scan example.com -s api.example.com -s admin.example.com
```

### Check Scan Status

```bash
# Check status
pentest status <scan-id>

# List recent scans
pentest list-scans
```

### View Configuration

```bash
pentest config
```

### Check Tools

```bash
pentest check-tools
```

## Configuration

Configuration is managed via `config/settings.yaml`:

```yaml
ai:
  provider: "ollama"
  model_name: "mistral"
  base_url: "http://localhost:11434"
  temperature: 0.3

rate_limits:
  requests_per_second: 10
  burst_limit: 20

scanning:
  nuclei_templates: "~/.nuclei-templates"
  severity_threshold: "low"

reporting:
  default_format: "pdf"
  company_name: "Your Company"
```

## Project Structure

```
petntesterai/
├── cli/                    # CLI interface
│   └── main.py            # Click commands
├── core/                   # Core modules
│   ├── config_manager.py  # Pydantic settings
│   ├── orchestrator.py    # Main pipeline
│   ├── auth_manager.py    # Target authorization
│   └── state_manager.py   # Checkpoint/resume
├── reconnaissance/         # Recon modules
│   ├── subdomain_enum.py
│   ├── port_scanner.py
│   ├── tech_detection.py
│   └── crawler.py
├── scanning/              # Vulnerability scanning
│   ├── vuln_scanner.py
│   └── modules/
│       ├── nuclei_runner.py
│       ├── header_security.py
│       ├── ssl_checker.py
│       └── cors_checker.py
├── ai_engine/             # AI components
│   ├── model_manager.py   # Ollama client
│   ├── analyzer.py        # Finding analysis
│   ├── false_positive_filter.py
│   ├── chain_detector.py
│   └── knowledge_base.py  # ChromaDB RAG
├── reporting/             # Report generation
│   └── report_generator.py
├── storage/               # Data persistence
│   ├── database.py        # SQLAlchemy models
│   └── encryption.py
├── utils/                 # Utilities
│   ├── logger.py          # Structlog setup
│   ├── rate_limiter.py
│   ├── validators.py
│   └── cvss_calculator.py
├── config/                # Configuration
│   └── settings.yaml
└── templates/             # Report templates
    └── professional.j2
```

## AI Capabilities

### False Positive Detection
Uses pattern matching and LLM analysis to identify likely false positives:
- Signature-based detection for common FP patterns
- Context-aware AI analysis for ambiguous cases
- Confidence scoring for findings

### Exploit Chain Detection
Identifies how multiple vulnerabilities can be combined:
- Pattern matching for known chains (SQLi + File Upload → RCE)
- AI-powered chain discovery
- Impact assessment for combined attacks

### Intelligent Prioritization
AI-driven severity adjustment based on:
- Business context and asset criticality
- Exploitability factors
- Real-world attack likelihood

## Development

### Running Tests

```bash
pytest tests/ -v
```

### Code Quality

```bash
# Format
black .
isort .

# Lint
ruff check .

# Type check
mypy .
```

## Security Considerations

⚠️ **Important**: Only use this tool against systems you have explicit permission to test.

- Always obtain written authorization before scanning
- The tool includes authorization checking (`pentest authorize`)
- Findings may contain sensitive information - handle reports securely
- Rate limiting is enabled by default to prevent service disruption

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## Acknowledgments

- [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner
- [Ollama](https://ollama.ai) - Local LLM inference
- [ChromaDB](https://www.trychroma.com/) - Vector database
