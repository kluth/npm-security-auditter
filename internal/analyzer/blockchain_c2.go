package analyzer

import (
	"fmt"
	"regexp"
)

// BlockchainC2Analyzer detects command and control infrastructure built on
// blockchain smart contracts, IPFS gateways, and decentralized storage.
// Based on the jest-fet-mock attack (ReversingLabs, July 2024) which used
// Ethereum smart contract getString() as an uncensorable C2 channel.
type BlockchainC2Analyzer struct{}

func NewBlockchainC2Analyzer() *BlockchainC2Analyzer {
	return &BlockchainC2Analyzer{}
}

func (a *BlockchainC2Analyzer) Name() string {
	return "blockchain-c2"
}

var blockchainC2Patterns = []struct {
	Pattern     *regexp.Regexp
	Title       string
	Description string
	Severity    Severity
}{
	// Web3/ethers imports in non-blockchain packages
	{
		regexp.MustCompile(`require\s*\(\s*['"](?:web3|ethers|@ethersproject/|hardhat|truffle-contract)['"]\s*\)`),
		"Blockchain library import",
		"Code imports blockchain interaction libraries. In non-blockchain packages, this indicates potential blockchain-based C2",
		SeverityHigh,
	},
	{
		regexp.MustCompile(`import\s+.*from\s+['"](?:web3|ethers|@ethersproject/)['"]\s*;?`),
		"Blockchain library import (ESM)",
		"Code imports blockchain libraries via ESM, suspicious in non-blockchain packages",
		SeverityHigh,
	},
	// Smart contract interaction patterns
	{
		regexp.MustCompile(`(?i)contract\.(getString|getData|getCommand|getPayload|getConfig|read|call)\s*\(`),
		"Smart contract data retrieval",
		"Code calls smart contract getter methods to retrieve data, the technique used in jest-fet-mock for C2 commands",
		SeverityCritical,
	},
	{
		regexp.MustCompile(`eth_call|eth_getStorageAt|eth_getLogs`),
		"Ethereum JSON-RPC call",
		"Code makes raw Ethereum JSON-RPC calls to read blockchain state, potentially fetching C2 commands",
		SeverityHigh,
	},
	// ABI definitions for simple getter contracts
	{
		regexp.MustCompile(`(?i)["'](?:function\s+)?(?:getString|getData|getCommand)\s*\(\s*\)[^'"]*(?:returns|view|pure)[^'"]*["']`),
		"Smart contract ABI for data retrieval",
		"Code defines a smart contract ABI with simple getter functions, matching the blockchain C2 pattern",
		SeverityCritical,
	},
	// IPFS gateway as payload delivery
	{
		regexp.MustCompile(`(?i)(?:ipfs\.io|cloudflare-ipfs\.com|gateway\.pinata\.cloud|dweb\.link|ipfs\.infura\.io)/ipfs/[A-Za-z0-9]+`),
		"IPFS gateway content fetch",
		"Code fetches content from an IPFS gateway. IPFS content is immutable and censorship-resistant, making it ideal for persistent C2",
		SeverityHigh,
	},
	// Arweave (permanent storage)
	{
		regexp.MustCompile(`(?i)arweave\.net/[A-Za-z0-9_-]{43}`),
		"Arweave permanent storage fetch",
		"Code fetches from Arweave, a permanent decentralized storage network. Content cannot be deleted, enabling persistent C2",
		SeverityHigh,
	},
	// Ethereum provider setup
	{
		regexp.MustCompile(`(?i)new\s+(?:Web3|ethers)\s*\.\s*providers?\s*\.\s*(?:JsonRpc|Http|Web3)\s*Provider\s*\(`),
		"Ethereum provider initialization",
		"Code initializes an Ethereum provider to interact with the blockchain",
		SeverityMedium,
	},
	// Infura/Alchemy provider URLs (common blockchain API endpoints)
	{
		regexp.MustCompile(`(?:mainnet|goerli|sepolia)\.infura\.io|eth-mainnet\.alchemyapi\.io|eth-mainnet\.g\.alchemy\.com`),
		"Blockchain API endpoint",
		"Code connects to a blockchain API provider, enabling smart contract interaction for potential C2",
		SeverityMedium,
	},
}

func (a *BlockchainC2Analyzer) scanContent(content, filename string) []Finding {
	var findings []Finding

	for _, pat := range blockchainC2Patterns {
		if pat.Pattern.MatchString(content) {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       pat.Title,
				Description: fmt.Sprintf("%s in file %q.", pat.Description, filename),
				Severity:    pat.Severity,
				ExploitExample: "Blockchain-based C2 is effectively uncensorable:\n" +
					"    1. Attacker deploys smart contract with getString() returning commands\n" +
					"    2. Malware calls contract.getString() to fetch C2 instructions\n" +
					"    3. Commands encoded as blockchain data persist forever\n" +
					"    4. No domain seizure or IP block can take down the C2\n" +
					"    Real: jest-fet-mock used Ethereum contract for C2 (ReversingLabs, July 2024)",
				Remediation: "Investigate why a non-blockchain package needs to interact with smart contracts. Extract the contract address and decode the stored data.",
			})
		}
	}

	return findings
}
