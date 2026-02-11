<div align="center">

# auditter

### The Advanced npm Security Auditor

**Deep forensic analysis for the npm supply chain.**\
**Detect malware, backdoors, and supply chain attacks before they reach production.**

[![CI](https://github.com/kluth/npm-security-auditter/actions/workflows/ci.yml/badge.svg)](https://github.com/kluth/npm-security-auditter/actions/workflows/ci.yml)
[![Release](https://github.com/kluth/npm-security-auditter/actions/workflows/release.yml/badge.svg)](https://github.com/kluth/npm-security-auditter/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/kluth/npm-security-auditter)](https://goreportcard.com/report/github.com/kluth/npm-security-auditter)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://github.com/kluth/npm-security-auditter)
[![Latest Release](https://img.shields.io/github/v/release/kluth/npm-security-auditter?color=blue)](https://github.com/kluth/npm-security-auditter/releases)
[![Tests](https://img.shields.io/badge/tests-381_passing-brightgreen)](#)

---

**40+ security analyzers** | **6 output formats** | **12 languages** | **Behavioral sandbox** | **AI summaries**

</div>

---

## Why auditter?

`npm audit` only checks for **known** CVEs. Real supply chain attacks use techniques that have never been seen before:

- A package that sleeps for 24 hours before activating its payload
- Install scripts that only run in CI/CD environments, not on developer machines
- Obfuscated code that decodes itself through 12 layers of eval chains
- Wallet addresses silently replaced on the clipboard
- Packages that steal your `.npmrc` tokens and publish worms under your name

**auditter** catches these. It performs deep forensic analysis of tarball contents, code patterns, metadata anomalies, and runtime behavior to detect zero-day supply chain threats.

---

## Installation

### Package managers

**macOS:**
```bash
# Download the Universal PKG from the latest release
curl -LO https://github.com/kluth/npm-security-auditter/releases/latest/download/auditter_v2.1.0_macOS_Universal.pkg
sudo installer -pkg auditter_v2.1.0_macOS_Universal.pkg -target /
```

**Debian / Ubuntu:**
```bash
curl -LO https://github.com/kluth/npm-security-auditter/releases/latest/download/auditter_2.1.0_linux_amd64.deb
sudo dpkg -i auditter_2.1.0_linux_amd64.deb
```

**Fedora / RHEL:**
```bash
curl -LO https://github.com/kluth/npm-security-auditter/releases/latest/download/auditter_2.1.0_linux_amd64.rpm
sudo rpm -i auditter_2.1.0_linux_amd64.rpm
```

**Arch Linux:**
```bash
curl -LO https://github.com/kluth/npm-security-auditter/releases/latest/download/auditter_2.1.0_linux_amd64.pkg.tar.zst
sudo pacman -U auditter_2.1.0_linux_amd64.pkg.tar.zst
```

**Alpine Linux:**
```bash
curl -LO https://github.com/kluth/npm-security-auditter/releases/latest/download/auditter_2.1.0_linux_amd64.apk
sudo apk add --allow-untrusted auditter_2.1.0_linux_amd64.apk
```

**Windows:**\
Download the [installer (.exe)](https://github.com/kluth/npm-security-auditter/releases/latest) or the ZIP archive and add to PATH.

### From source

Requires Go 1.23+:
```bash
go install github.com/kluth/npm-security-auditter/cmd/auditter@latest
```

### All platforms

See the [Releases page](https://github.com/kluth/npm-security-auditter/releases) for pre-built binaries for Linux, macOS, and Windows (amd64 + arm64).

---

## Quick start

```bash
# Audit a single package
auditter express

# Audit your project
auditter -p package.json

# Audit everything in node_modules
auditter --node-modules

# Only show critical/high findings, output as JSON
auditter lodash -s high --json

# Full project audit with PDF report and AI summary
auditter -p package-lock.json --format pdf -o report.pdf --ai-summary
```

---

## Usage

```
auditter <package-name> [flags]
```

### Flags

| Flag | Short | Description | Default |
|:---|:---:|:---|:---|
| `--project` | `-p` | Path to `package.json` or `package-lock.json` | - |
| `--node-modules` | | Audit all dependencies from `node_modules/` | `false` |
| `--format` | | Output: `terminal`, `json`, `markdown`, `html`, `csv`, `pdf` | `terminal` |
| `--json` | | Alias for `--format json` | `false` |
| `--severity` | `-s` | Minimum severity: `low`, `medium`, `high`, `critical` | `low` |
| `--lang` | | Report language (see below) | `en` |
| `--interactive` | `-i` | Launch TUI mode (Bubble Tea) | `false` |
| `--ai-summary` | | Generate AI analysis via Gemini CLI | `false` |
| `--no-sandbox` | | Disable dynamic analysis | `false` |
| `--concurrency` | `-c` | Max concurrent package audits | `5` |
| `--timeout` | | Timeout per package (seconds) | `180` |
| `--registry` | `-r` | Custom npm registry URL | npmjs.org |
| `--output` | `-o` | Write report to file | stdout |
| `--verbose` | `-v` | Show all individual findings | `false` |

### Languages

| Standard | | | | |
|:---|:---|:---|:---|:---|
| `en` English | `de` German | `fr` French | `es` Spanish | `it` Italian |
| `pt` Portuguese | `jp` Japanese | `zh` Chinese | `ru` Russian | |

| Easter eggs | | |
|:---|:---|:---|
| `tlh` Klingon | `vul` Vulcan | `sin` Sindarin |

---

## Security analyzers

auditter ships with **40+ analyzers** organized into layers of defense. Each analyzer is research-backed and tested against real-world malware samples.

### Supply chain & metadata

| Analyzer | What it detects |
|:---|:---|
| **Vulnerability database** | Known CVEs from the npm advisory database |
| **Typosquatting** | Levenshtein distance comparison against top 500 packages |
| **Slopsquatting** | LLM-hallucinated package names (`react-utils-helper`, `express-auth-middleware`) |
| **Manifest confusion** | Mismatches between registry metadata and tarball `package.json` (hidden scripts, phantom deps) |
| **Star-jacking** | New packages linking to popular repos they don't own for fake credibility |
| **Version anomalies** | Rapid publishing, major version jumps, dormant package revival, unpublished versions |
| **Remote dependencies** | HTTP URLs, git URLs, `file:` paths in dependency fields (PhantomRaven attack) |
| **Community trust** | Missing repo/license/README, single maintainer, no description |

### Code analysis (tarball forensics)

| Analyzer | What it detects |
|:---|:---|
| **AST-based deep analysis** | Dynamic `require()`, string concatenation evasion, computed property access, `Function` constructor, `fromCharCode` chains |
| **Taint analysis** | Data flow from sources (`process.env`, `fs.read`, network) to sinks (`eval`, `exec`, `fetch`) |
| **Multi-layer obfuscation** | Nested eval chains, XOR ciphers, self-decoding IIFE wrappers, heavy hex escapes, non-ASCII identifiers |
| **Anti-debug evasion** | Debugger traps, timing-based detection, console overrides, `v8debug`/`--inspect` flag checks |
| **Prototype pollution** | `__proto__` access, `constructor.prototype` manipulation, unsafe recursive merge, `Object.defineProperty` on prototypes |
| **Environment fingerprinting** | CI/CD variable probing, cloud metadata detection, VM/sandbox detection, container escape |
| **AI evasion** | Techniques designed to bypass AI-based code review (prompt injection, obfuscated patterns) |
| **Behavior sequences** | Multi-step attack chains (read env -> encode -> exfiltrate) |

### Malware patterns

| Analyzer | What it detects |
|:---|:---|
| **Multi-stage loaders** | Fetch + eval droppers, write-to-disk-and-execute, dynamic `import()` from URLs |
| **Time-bombs** | Date-based activation, long `setTimeout` delays (>1h), weekday-gated payloads, production-only execution |
| **Cryptocurrency theft** | Wallet addresses, clipboard hijacking, `.ethereum`/`.bitcoin` keystore theft, seed phrase capture |
| **Phishing infrastructure** | Fake login forms, IDE credential harvesting (VS Code), domain spoofing, keyloggers |
| **Self-replicating worms** | `npm publish` execution, `.npmrc` token theft, git credential theft, `package.json` injection |
| **Phantom dependencies** | `require()` calls for modules not in `package.json`, dangerous builtin combinations |
| **Exfiltration** | DNS tunneling, webhook exfil, `sendBeacon`, base64-encoded POST bodies |

### Build integrity & provenance

| Analyzer | What it detects |
|:---|:---|
| **Code signing** | Missing/weak registry signatures, SLSA provenance verification |
| **Reproducible builds** | Integrity hash verification, attestation presence, source repository linkage |
| **Provenance** | SLSA build attestation verification |
| **Scorecard** | OpenSSF Scorecard integration |

### Runtime & structural

| Analyzer | What it detects |
|:---|:---|
| **Install scripts** | `preinstall`/`postinstall` hooks running `curl`, `wget`, `sh`, `powershell` |
| **Shell scripts** | Embedded shell scripts with network calls, credential access, persistence |
| **Dynamic analysis (sandbox)** | Real-time monitoring of network calls, filesystem changes, process spawning (Linux) |
| **Tarball forensics** | Hidden files (`.env`, `.npmrc`), binaries, encoded payloads, high entropy, malware signatures |
| **Dangerous extensions** | `.exe`, `.dll`, `.so`, `.sh` files that shouldn't be in npm packages |
| **Lockfile integrity** | Tampered or inconsistent lockfile entries |
| **Minified-only packages** | Packages shipping only minified code with no source |
| **Commit history** | Suspicious patterns in git commit history |
| **Download anomalies** | Unusual download patterns and reputation scoring |

### Research references

The analyzers are based on techniques from:

- **USENIX Security 2021** - "Detecting JavaScript Anti-Debugging Techniques in the Wild"
- **USENIX Security 2022** - "Silent Spring: Prototype Pollution Leads to RCE"
- **USENIX Security 2024** - DONAPI: Behavior Sequence Knowledge Mapping
- **BlackHat 2023** - Prototype pollution to RCE escalation
- **Socket.dev** - Phantom dependency and supply chain attack research
- **Phylum / Veracode** - Slopsquatting and LLM-hallucinated package detection
- **Datadog / Checkmarx** - Delayed activation supply chain attacks
- **Wiz / Cycode** - 12-stage npm dropper analysis
- **Sonatype** - npm crypto-stealer campaign tracking
- **Aikido** - Developer-targeted phishing campaigns

---

## Output formats

| Format | Flag | Use case |
|:---|:---|:---|
| **Terminal** | `--format terminal` | Interactive review with colored output |
| **JSON** | `--format json` | CI/CD pipelines, automated processing |
| **Markdown** | `--format markdown` | GitHub issues, documentation |
| **HTML** | `--format html` | Browser-viewable reports |
| **CSV** | `--format csv` | Spreadsheet import, data analysis |
| **PDF** | `--format pdf` | Formal audit reports, compliance |

---

## CI/CD integration

### GitHub Actions

```yaml
- name: Security audit
  run: |
    curl -LO https://github.com/kluth/npm-security-auditter/releases/latest/download/auditter_2.1.0_linux_amd64.tar.gz
    tar xzf auditter_2.1.0_linux_amd64.tar.gz
    ./auditter -p package-lock.json -s high --json > audit.json

- name: Fail on critical findings
  run: |
    if jq -e '.reports[].results[].findings[] | select(.severity == "CRITICAL")' audit.json > /dev/null 2>&1; then
      echo "::error::Critical security findings detected"
      exit 1
    fi
```

### GitLab CI

```yaml
security_audit:
  image: golang:1.23
  script:
    - go install github.com/kluth/npm-security-auditter/cmd/auditter@latest
    - auditter -p package-lock.json -s high --json > audit.json
  artifacts:
    paths:
      - audit.json
```

### Shell one-liner

```bash
# Fail if any critical findings
auditter -p package.json -s critical --json | jq -e '.reports | length == 0'
```

---

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and pull request guidelines.

## Security

For vulnerability reports, see [SECURITY.md](SECURITY.md).

## License

Licensed under the [MIT License](LICENSE).
