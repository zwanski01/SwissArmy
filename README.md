# 🔪 SwissArmyGo - Comprehensive Security Assessment Toolkit

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![GitHub Issues](https://img.shields.io/github/issues/zwanski01/SwissArmy?style=flat-square)](https://github.com/zwanski01/SwissArmy/issues)
[![GitHub Stars](https://img.shields.io/github/stars/zwanski01/SwissArmy?style=flat-square)](https://github.com/zwanski01/SwissArmy/stargazers)

A multi-functional security tool written in Go, inspired by the versatility of the Swiss Army knife. Designed for bug bounty hunters, penetration testers, and security professionals.

> **Inspired by**: The Victorinox Swiss Army Knife philosophy - packing multiple tools into a compact, efficient package

## ✨ Features

### 🎯 Security Assessment
- **Vulnerability Scanning**: SQLi, XSS, SSRF, LFI/RFI testing
- **Subdomain Enumeration**: DNS-based subdomain discovery
- **Directory Bruteforcing**: Find hidden directories and files
- **Port Scanning**: Identify open ports and services
- **Technology Detection**: Fingerprint web technologies

### 📊 Analysis & Reporting
- **Security Header Analysis**: Check for missing security headers
- **Sensitive Data Exposure**: Scan for exposed secrets and information
- **JSON Report Generation**: Structured output for automation
- **Multiple Output Formats**: Human-readable and machine-parsable

### ⚡ Performance
- **Multi-threaded Execution**: High-performance concurrent scanning
- **Configurable Timeouts**: Adjustable for different network conditions
- **Stealth Mode**: Reduced noise for covert operations
- **Resume Capability**: Continue interrupted scans

## 🛠️ Installation

### Prerequisites
- **Go 1.21+**: [Install Guide](https://golang.org/doc/install)
- **Kali Linux** (recommended) or any Linux distribution

### From Source
```bash
git clone https://github.com/zwanski01/SwissArmy.git
cd SwissArmy
go mod download
go build -o swissarmygo main.go
sudo mv swissarmygo /usr/local/bin/
```

#### Using Makefile
```bash
make build      # Build for current platform
make release    # Build for all platforms
make deps       # Install dependencies
make clean      # Clean build artifacts
```

## 🚀 Usage

Basic Scan:
```bash
./swissarmygo -u https://example.com -o scan_results.json
```

Full Assessment:
```bash
./swissarmygo -u https://example.com -m full -o full_scan.json -v
```

Stealth Mode:
```bash
./swissarmygo -u https://example.com -m stealth -t 10 -o stealth_scan.json
```

Advanced Options:
```bash
# Custom wordlists
./swissarmygo -u https://example.com -wordlist subdomains.txt -o scan.json

# Specific ports only
./swissarmygo -u https://example.com -ports 80,443,8080 -o scan.json

# Custom headers
./swissarmygo -u https://example.com -H "Authorization: Bearer token" -o scan.json
```

### 📊 Output Example
```json
{
  "target": "https://example.com",
  "scan_date": "2025-09-01T10:30:00Z",
  "findings": [
    {
      "type": "SQL Injection",
      "url": "https://example.com/login?username=admin'",
      "parameter": "username",
      "payload": "admin' OR '1'='1",
      "evidence": "MySQL syntax error",
      "severity": "High",
      "confidence": "Medium"
    }
  ],
  "statistics": {
    "total_requests": 1245,
    "scan_duration": "2m45s",
    "vulnerabilities_found": 3
  }
}
```

## 🗂️ Recommended Repository Structure

SwissArmy/
├── main.go                 # Main application code
├── go.mod                 # Go module definition
├── go.sum                 # Dependency checksums
├── README.md              # Project documentation
├── LICENSE                # MIT License
├── .gitignore            # Git ignore rules
├── Makefile              # Build automation
├── bin/                  # Compiled binaries
├── pkg/                  # Library code
├── cmd/                  # Additional commands
├── internal/             # Internal packages
├── configs/              # Configuration files
├── scripts/              # Utility scripts
├── examples/             # Usage examples
└── docs/                 # Additional documentation

## 🏗️ Architecture

SwissArmyGo
├── Core Engine
│   ├── Scanner Manager
│   ├── Vulnerability Modules
│   ├── Network Utilities
│   └── Report Generator
├── Modules
│   ├── Subdomain Scanner
│   ├── Port Scanner
│   ├── Web Vulnerability Scanner
│   ├── Technology Detector
│   └── Data Exfiltration Detector
└── Utilities
    ├── HTTP Client
    ├── DNS Resolver
    ├── Concurrency Manager
    └── Configuration Parser

## 🤝 Contributing

We welcome contributions! Please see our Contributing Guide for details.

### Development Setup
```bash
git clone https://github.com/your-username/SwissArmy.git
cd SwissArmy
git checkout -b feature/amazing-feature
go test ./...
git commit -m "Add amazing feature"
git push origin feature/amazing-feature
# Create Pull Request
```

### Adding New Modules

1. Create a new file in `pkg/modules/`
2. Implement the Module interface
3. Register the module in `pkg/modules/registry.go`
4. Add tests in `pkg/modules/modulename_test.go`

## 📋 TODO & Roadmap

- Additional vulnerability checks
- API security testing
- Cloud configuration auditing
- CI/CD integration
- Docker support
- Web interface
- Plugin system

## 🐛 Troubleshooting

**Common Issues**

- Build failures: Ensure you have Go 1.21+ installed
  ```bash
  go version
  ```
- Network timeouts: Adjust timeout settings
  ```bash
  ./swissarmygo -u https://example.com -timeout 30
  ```
- Permission issues: Run with appropriate privileges
  ```bash
  sudo setcap cap_net_raw+ep $(which swissarmygo)
  ```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Inspired by the versatility of Swiss Army knives
- Thanks to the Go community for excellent libraries
- Security researchers worldwide for their contributions

## 📞 Support

- GitHub Issues: Report bugs or request features
- Email: contact@zwanski.org
- Discord: zwanski

## ⚠️ Disclaimer

This tool is intended for security testing and educational purposes only. Only use on systems you own or have explicit permission to test. The developers are not responsible for misuse or damage caused by this program.

Legal Note: Always comply with local laws and regulations when conducting security assessments.
