package reporter

import (
	"encoding/json"
	"fmt"

	"github.com/kluth/npm-security-auditter/internal/analyzer"
)

// SARIF Schema Structs (simplified for our needs)
// Schema: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json

type sarifLog struct {
	Version string      `json:"version"`
	Schema  string      `json:"$schema"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool      sarifTool        `json:"tool"`
	Results   []sarifResult    `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string       `json:"name"`
	Version         string       `json:"version"`
	InformationUri  string       `json:"informationUri"`
	Rules           []sarifRule  `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name,omitempty"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  sarifMessage        `json:"fullDescription,omitempty"`
	Help             sarifMessage        `json:"help,omitempty"`
	Properties       sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	Tags     []string `json:"tags,omitempty"`
	Severity string   `json:"security-severity,omitempty"`
}

type sarifResult struct {
	RuleID      string          `json:"ruleId"`
	Level       string          `json:"level"` // error, warning, note, none
	Message     sarifMessage    `json:"message"`
	Locations   []sarifLocation `json:"locations,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
}

type sarifMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

// renderSARIF outputs the report in SARIF format.
func (r *Reporter) renderSARIF(report Report) error {
	run := sarifRun{
		Tool: sarifTool{
			Driver: sarifDriver{
				Name:           "npm-security-auditter",
				Version:        "2.3.2", // Should inject this ideally
				InformationUri: "https://github.com/kluth/npm-security-auditter",
				Rules:          []sarifRule{},
			},
		},
		Results: []sarifResult{},
	}

	// Map rules from analyzers
	ruleMap := make(map[string]bool)
	
	allFindings := collectFindings(report.Results)
	
	for _, f := range allFindings {
		ruleID := f.Analyzer
		if !ruleMap[ruleID] {
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID: ruleID,
				Name: f.Title,
				ShortDescription: sarifMessage{Text: f.Title},
				FullDescription: sarifMessage{Text: f.Description},
				Help: sarifMessage{
					Text: fmt.Sprintf("%s\n\nRemediation: %s", f.Description, f.Remediation),
					Markdown: fmt.Sprintf("**%s**\n\n%s\n\n### Remediation\n%s", f.Title, f.Description, f.Remediation),
				},
				Properties: sarifRuleProperties{
					Tags: []string{"security", "npm", "supply-chain"},
					Severity: getSarifSeverityScore(f.Severity),
				},
			})
			ruleMap[ruleID] = true
		}

		level := "warning"
		if f.Severity == analyzer.SeverityCritical || f.Severity == analyzer.SeverityHigh {
			level = "error"
		} else if f.Severity == analyzer.SeverityLow {
			level = "note"
		}

		run.Results = append(run.Results, sarifResult{
			RuleID: ruleID,
			Level:  level,
			Message: sarifMessage{
				Text: fmt.Sprintf("[%s] %s: %s", f.Severity, f.Title, f.Description),
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: "package.json", // Default to package manifest since we analyze the package concept
						},
					},
				},
			},
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
		Runs:    []sarifRun{run},
	}

	enc := json.NewEncoder(r.writer)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func getSarifSeverityScore(s analyzer.Severity) string {
	switch s {
	case analyzer.SeverityCritical:
		return "9.0"
	case analyzer.SeverityHigh:
		return "7.0"
	case analyzer.SeverityMedium:
		return "5.0"
	case analyzer.SeverityLow:
		return "3.0"
	default:
		return "1.0"
	}
}
