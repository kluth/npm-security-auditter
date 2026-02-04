# auditter: The Advanced npm Security Auditor

[![CI](https://github.com/kluth/npm-security-auditter/actions/workflows/ci.yml/badge.svg)](https://github.com/kluth/npm-security-auditter/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/kluth/npm-security-auditter)](https://goreportcard.com/report/github.com/kluth/npm-security-auditter)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod/go-version/kluth/npm-security-auditter)](https://github.com/kluth/npm-security-auditter)

**auditter** is a comprehensive, declarative security analysis tool for npm packages. Unlike standard vulnerability scanners that only check database records, `auditter` performs deep forensic analysis of the package tarball, metadata, and code patterns to detect supply chain attacks, malicious payloads, and sophisticated obfuscation techniques.

![Audit Demo](https://via.placeholder.com/800x400?text=Auditter+CLI+Demo+Screenshot)

## 🚀 Features

*   **🕵️ Deep Tarball Forensics**: Scans for hidden files, binary executables, and unexpected content not listed in the registry.
*   **🧠 Heuristic Code Analysis**:
    *   **Entropy Checks**: Detects high-complexity strings (potential encrypted payloads).
    *   **Obfuscation Detection**: Flags minified code, hex-encoded strings, and suspicious variable naming.
    *   **Typosquatting Detection**: Identifies packages mimicking popular libraries (e.g., `react` vs `raect`).
*   **📦 Dependency Tree Analysis**:
    *   **Circular Dependencies**: Detects self-referencing loops.
    *   **Dependency Confusion**: Flags internal-looking package names in public manifests.
    *   **Tree Depth & Bloat**: Warns about excessive or deep dependency chains.
*   **⚖️ License Compliance**: Identifying copyleft (GPL, AGPL) and unconventional licenses.
*   **⏰ Temporal Analysis**:
    *   **Recent Publish Alert**: Flags versions published < 24h ago (high-risk window for malware).
    *   **Dormancy Checks**: Detects sudden activity after long inactivity (account takeover indicator).
*   **🛡️ Provenance Verification**: Checks for SLSA build attestations.
*   **🧪 Dynamic Sandbox (Optional)**: Safe execution of install scripts to monitor behavioral indicators (network, filesystem).

## 📥 Installation

### From Source

Requires Go 1.23+:

```bash
go install github.com/kluth/npm-security-auditter/cmd/auditter@latest
```

### Manual Build

```bash
git clone https://github.com/kluth/npm-security-auditter.git
cd npm-security-auditter
go build -o auditter cmd/auditter/main.go
```

## 🛠️ Usage

### Audit a Single Package

Check a specific package from the npm registry:

```bash
auditter express
```

### Audit a Local Project

Scan your entire `package.json` or `node_modules` directory:

```bash
# Scan dependencies defined in package.json
auditter --project package.json

# Deep scan of installed node_modules
auditter --node-modules
```

### Options

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-p, --project` | Path to `package.json` or `package-lock.json` | - |
| `-r, --registry` | Custom npm registry URL | `https://registry.npmjs.org` |
| `--no-sandbox` | Disable dynamic analysis (faster, less thorough) | `false` |
| `--format` | Output format (`terminal`, `json`, `markdown`) | `terminal` |
| `--lang` | Report language (`en`, `de`, `fr`, etc.) | `en` |
| `-v, --verbose` | Enable verbose logging | `false` |

## 📊 Analyzers

`auditter` runs a suite of specialized analyzers:

1.  **`tarball-analysis`**: The core forensic engine. Checks file content, entropy, and hidden artifacts.
2.  **`metadata`**: Validates registry metadata against package content (name mismatches, version anomalies).
3.  **`maintainers`**: Assesses maintainer reputation, email domains, and ownership changes.
4.  **`typosquatting`**: Compares package name against top 10k npm packages.
5.  **`dependencies`**: Reviews dependency tree for confusion attacks and version locking issues.
6.  **`install-scripts`**: Static analysis of `preinstall`/`postinstall` scripts for malicious patterns (curl | bash).
7.  **`provenance`**: Verifies sigstore/SLSA signatures.
8.  **`dynamic-analysis`**: (Sandbox) Monitors system calls during installation.

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on how to submit pull requests and report issues.

## 🔒 Security

For security policy and vulnerability reporting, please see [SECURITY.md](SECURITY.md).

## 📄 License

This project is licensed under the [MIT License](LICENSE).
