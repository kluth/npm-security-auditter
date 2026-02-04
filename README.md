# auditter: The Advanced npm Security Auditor

[![CI](https://github.com/kluth/npm-security-auditter/actions/workflows/ci.yml/badge.svg)](https://github.com/kluth/npm-security-auditter/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/kluth/npm-security-auditter)](https://goreportcard.com/report/github.com/kluth/npm-security-auditter)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod/go-version/kluth/npm-security-auditter)](https://github.com/kluth/npm-security-auditter)
[![Releases](https://img.shields.io/github/v/release/kluth/npm-security-auditter)](https://github.com/kluth/npm-security-auditter/releases)

**auditter** is a professional-grade, declarative security analysis tool for the npm ecosystem. It goes beyond simple database lookups, performing deep forensics on package tarballs, metadata anomalies, and code patterns to proactively identify supply chain attacks.

## 🚀 Key Features

*   **🕵️ Deep Tarball Forensics**: Scans for hidden files (`.env`, `.npmrc`), binary executables, and unexpected content not present in the registry metadata.
*   **🧠 Heuristic Code Analysis**: 
    *   **Complexity (Entropy) Analysis**: Detects highly randomized data chunks which often hide encrypted or obfuscated payloads.
    *   **Obfuscation Detection**: Identifies minification tricks, hex-encoded properties, and suspicious `eval`/`Function` usage.
*   **📦 Dependency Health**: Detects circular dependencies, dependency confusion risks, and unsafe version ranges (`*`, `latest`).
*   **⏰ Lifecycle Analysis**: Flags versions published in the high-risk "malware window" (< 24h) or sudden activity after long dormancy.
*   **🛡️ Provenance & Trust**: Verifies SLSA build attestations and maintainer reputation (disposable emails, single-maintainer risks).
*   **🧪 Behavioral Sandbox**: (Linux only) Safe execution of install scripts to monitor network calls and filesystem changes.

## 📥 Installation

### Download Binaries
Download pre-compiled binaries for **Linux, Windows, and macOS** from the [Releases Page](https://github.com/kluth/npm-security-auditter/releases).

### From Source
Requires Go 1.23+:
```bash
go install github.com/kluth/npm-security-auditter/cmd/auditter@latest
```

## 🛠️ Detailed Usage

```bash
auditter <package-name> [flags]
```

### Example Commands

#### 🟢 Basic
Audit a specific package from the registry:
```bash
auditter express
```

Audit your current project using `package.json`:
```bash
auditter -p package.json
```

#### 🟡 Intermediate
Audit with high-severity focus and save as Markdown:
```bash
auditter lodash --severity high --format markdown -o report.md
```

Run a deep audit of all installed dependencies in German:
```bash
auditter --node-modules --lang de
```

#### 🔴 Advanced & Chained
Audit a project with 10 concurrent workers, a 5-minute timeout, and no sandbox (for speed), outputting to JSON:
```bash
auditter -p package.json -c 10 --timeout 300 --no-sandbox --json > audit.json
```

**Automation Pipeline**: Check for critical findings and fail if any are found (using `jq`):
```bash
auditter express --json | jq -e '.findings[] | select(.severity == "critical")' > /dev/null || echo "Critical vulnerabilities found!"
```

#### 🖖 Just for Fun
Audit in Klingon:
```bash
auditter react --lang tlh
```

### Full Flag Reference

| Flag | Shorthand | Description | Default |
| :--- | :---: | :--- | :--- |
| `--project` | `-p` | Path to `package.json` or `package-lock.json` for full project audit | - |
| `--node-modules` | - | Recursively audit all dependencies found in local `node_modules/` | `false` |
| `--format` | - | Output format: `terminal`, `json`, `markdown`, `html`, `csv`, `pdf` | `terminal` |
| `--json` | - | Shortcut for `--format json` | `false` |
| `--severity` | `-s` | Minimum severity level to report: `low`, `medium`, `high`, `critical` | `low` |
| `--lang` | - | Localization for the report (see list below) | `en` |
| `--no-sandbox` | - | Disable dynamic analysis (no container execution) | `false` |
| `--concurrency`| `-c` | Max concurrent package audits | `5` |
| `--timeout` | - | Timeout in seconds for each package audit | `180` |
| `--registry` | `-r` | Custom npm registry URL | `https://registry.npmjs.org` |
| `--interactive`| `-i` | Launch the interactive TUI mode (Bubble Tea powered) | `false` |
| `--output` | `-o` | Write the report to a specific file | `stdout` |
| `--verbose` | `-v` | Enable detailed debug logging | `false` |
| `--version` | - | Display current version and exit | - |

### Supported Languages (`--lang`)
`auditter` supports standard and "fun" localizations for its reports:
*   🌍 **Standard**: `en` (English), `de` (German), `fr` (French), `es` (Spanish), `it` (Italian), `pt` (Portuguese), `jp` (Japanese), `zh` (Chinese), `ru` (Russian).
*   🖖 **Easter Eggs**: `tlh` (Klingon), `vul` (Vulcan), `sin` (Sindarin/Elvish).

## 📊 Security Analyzers

1.  **`tarball-analysis`**: Inspects the actual payload. Flags large files (>1MB), hidden directories, and suspicious JS patterns.
2.  **`metadata`**: Checks for description/README mismatches between npm and GitHub, and flags deprecated versions.
3.  **`maintainers`**: Identifies "Disposable Email" domains and "Sudden Activity after Inactivity" (Account Takeover indicator).
4.  **`typosquatting`**: Uses character-difference algorithms to find packages mimicking `lodash`, `express`, `react`, etc.
5.  **`dependencies`**: Analyzes the tree for "Dependency Confusion" (internal-looking names in public registries).
6.  **`install-scripts`**: Static analysis of `preinstall` scripts for `curl`, `wget`, or `sh` execution.
7.  **`provenance`**: Verifies SLSA signatures to ensure the package was built on a trusted CI (like GitHub Actions).
8.  **`dynamic-analysis`**: Executes the package in a restricted sandbox to track real-time system calls.

## 🤝 Contributing
Please see [CONTRIBUTING.md](CONTRIBUTING.md) for local development setup and pull request guidelines.

## 📄 License
Licensed under the [MIT License](LICENSE).