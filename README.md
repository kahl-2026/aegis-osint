# AegisOSINT

**Educational CLI platform for authorized bug bounty workflows and defensive OSINT operations.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

## ⚠️ Legal Disclaimer

**IMPORTANT: This tool is designed for AUTHORIZED security testing only.**

- **Only use AegisOSINT on systems you have explicit written permission to test**
- **Unauthorized computer access is illegal** and may result in civil and criminal penalties
- Always follow your bug bounty program's rules and scope definitions
- This tool is for reconnaissance only—it does NOT perform exploitation

By using this software, you acknowledge that you understand and will comply with all applicable laws and regulations.

## Features

### Offensive OSINT (Bug Bounty)
- **Asset Discovery**: CT log enumeration, DNS resolution, ASN mapping
- **Web Reconnaissance**: Header analysis, endpoint discovery, technology fingerprinting
- **Cloud Exposure**: S3/Azure/GCP bucket enumeration, public repo scanning
- **Expanded Intelligence Suites**: DNS intelligence, repository intelligence, TLS/infrastructure intelligence, leak/mention intelligence
- **Run Telemetry & Evidence**: Per-module asset/finding/evidence breakdown persisted per scan run
- **Scope Enforcement**: Hard validation of authorized targets before any operation

### Defensive OSINT (Blue Team)
- **Attack Surface Monitoring**: Continuous external asset inventory
- **Drift Detection**: Configuration changes, DNS modifications, certificate updates
- **Brand Monitoring**: Typosquatting detection, homoglyph analysis
- **Leak Monitoring**: Public exposure indicators

### Safety & Compliance
- **Scope Validation**: Every operation validates against authorized scope
- **Rate Limiting**: Configurable request budgets with burst protection
- **Kill Switch**: Global emergency stop capability
- **Audit Logging**: Full provenance trail for all operations
- **Non-Destructive**: Reconnaissance-focused, no exploitation capabilities

## Installation

### Prerequisites
- Rust 1.70+
- SQLite 3.x (or PostgreSQL 12+ for production)

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/aegis-osint.git
cd aegis-osint

# Build
make build

# Or with cargo directly
cargo build --release

# Install globally
cargo install --path .
```

### Setup Script (Linux)

```bash
# Auto-detect distro and install dependencies
./setup.sh

# Or manually:
# Arch: sudo pacman -S base-devel sqlite openssl bind whois pkg-config git curl
# Debian/Ubuntu: sudo apt install build-essential libsqlite3-dev libssl-dev dnsutils whois pkg-config git curl ca-certificates
# Fedora: sudo dnf install gcc sqlite-devel openssl-devel bind-utils whois pkgconfig git curl
```

The interactive CLI experience uses a full-screen keyboard-first TUI (ratatui/crossterm) with a compact top status bar, richer context panels, and arrow/enter/esc navigation for faster workflows.

## Quick Start

### 1. Initialize (First Run)

```bash
# First run requires authorization acknowledgment
aegis init
```

### 2. Import Scope

```bash
# Import a scope definition file
aegis scope import --file scope.yaml

# List active scopes
aegis scope list
```

### 3. Run Offensive Recon

```bash
# Standard reconnaissance profile
aegis offensive run --program "HackerOne Example" --scope scope-id-123 --profile standard

# Safe profile (lower rate, passive only)
aegis offensive run --program "Example" --scope scope-id-123 --profile safe

# Aggressive profile (expanded active probing, explicit opt-in)
aegis offensive run --program "Example" --scope scope-id-123 --profile aggressive
```

Thorough (Deep) and Aggressive profiles execute the full available module stack, including dedicated OSINT intelligence suites.

### 4. Monitor Defensively

```bash
# Start continuous monitoring
aegis defensive monitor --scope scope-id-123
```

### 5. Review Findings

```bash
# List findings by severity
aegis findings list --severity high

# Verify a specific finding
aegis findings verify --id finding-abc-123
```

### 6. Export Reports

```bash
# Export JSON technical report
aegis report export --format json --output report.json

# Export bug bounty submission format
aegis report export --format bounty --output submission.md
```

## Command Reference

### Scope Management
```
aegis scope import --file <path>     Import scope from YAML file
aegis scope list                      List all scopes
aegis scope show <scope-id>           Show scope details
aegis scope validate --file <path>    Validate scope file syntax and policy
aegis scope delete <scope-id>         Delete a scope
aegis scope export <scope-id> --output <path>
```

### Offensive Operations
```
aegis offensive run --program <name> --scope <id> [--profile safe|standard|thorough|aggressive]
aegis offensive status --run-id <id>
aegis offensive stop --run-id <id>
```

### Defensive Operations
```
aegis defensive monitor --scope <id>  Start monitoring
aegis defensive scan --scope <id>     Run one-time defensive scan
aegis defensive status [--scope <id>] Show monitor status
aegis defensive alerts --scope <id> --show
aegis defensive summary --scope <id>
```

### Findings
```
aegis findings list [--severity <level>] [--status <status>]
aegis findings show --id <finding-id>
aegis findings verify --id <finding-id>
aegis findings update --id <finding-id> --status <status>
```

### Assets
```
aegis assets list [--scope <id>]
aegis assets diff --scope <id> --since <date>
aegis assets show <asset-id> [--history] [--findings]
aegis assets tag <asset-id> --add tag1,tag2
aegis assets export --scope <id> --format json
```

### Reports
```
aegis report export --format json|markdown|html --output <path>
aegis report summary --scope <id> [--period 30d]
aegis report templates [--verbose]
```

### System
```
aegis doctor                         Health check
aegis init                           First-run authorization flow
aegis menu                           Launch full-screen interactive TUI
```

In the interactive TUI, the **OSINT Toolkit** menu provides dedicated suite execution options:
- DNS Intelligence Suite
- Repository Intelligence Suite
- TLS/Infrastructure Intelligence Suite
- Leak/Mention Intelligence Suite
- Full-suite execution with run-level module/evidence breakdown

## Scope File Format

```yaml
id: "example-bounty"
name: "Example Bug Bounty"

program:
  name: "Example Bug Bounty"
  platform: "hackerone"
  url: "https://hackerone.com/example"

in_scope:
  domains:
    - "*.example.com"
    - "api.example.com"
  cidrs:
    - "203.0.113.0/24"
  urls:
    - "https://app.example.com/"
  exclude:
    - "admin.example.com"

out_of_scope:
  domains:
    - "admin.example.com"
  cidrs:
    - "10.0.0.0/8"

rules:
  allowed:
    - "passive_recon"
  prohibited:
    - "brute_force"
  rate_limits:
    requests_per_second: 10
```

See [fixtures/scope.yaml](fixtures/scope.yaml) for a complete example.

## Policy Configuration

```yaml
safety:
  kill_switch:
    enabled: false
  require_scope_validation: true
  max_risk_level: "high"

rate_limits:
  global:
    requests_per_second: 50
    burst: 100
```

See [fixtures/policy.yaml](fixtures/policy.yaml) for a complete example.

## Architecture

```
aegis-osint/
├── src/
│   ├── cli/          # Command definitions
│   ├── config/       # Configuration management
│   ├── scope/        # Scope parsing & validation
│   ├── policy/       # Safety guardrails
│   ├── storage/      # Database backends
│   ├── offensive/    # Offensive OSINT modules
│   ├── defensive/    # Defensive OSINT modules
│   ├── findings/     # Finding management
│   ├── reporting/    # Report generation
│   └── utils/        # Shared utilities
├── tests/            # Integration tests
└── fixtures/         # Example configurations
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | General error |
| 2    | Scope violation |
| 3    | Policy violation |
| 4    | Configuration error |
| 5    | Storage error |
| 6    | Network error |
| 7    | Authorization required |
| 8    | Invalid input |

## Development

```bash
# Run tests
make test

# Run with coverage
make coverage

# Lint
make lint

# Full validation
make validate
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for our security policy and reporting vulnerabilities.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Inspired by tools like amass, subfinder, and nuclei
- Built with security-first principles for the bug bounty community
- Designed for both offensive and defensive security teams
