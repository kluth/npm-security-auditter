package analyzer

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// UnicodeSteganographyAnalyzer detects hidden payloads encoded via Unicode
// variation selectors, tag characters, and other invisible Unicode ranges.
// Based on the os-info-checker-es6 attack (May 2025) which used variation
// selectors from the Supplement block (U+E0100-U+E01EF) to embed a hidden
// base64 payload invisible to editors and diff viewers.
type UnicodeSteganographyAnalyzer struct{}

func NewUnicodeSteganographyAnalyzer() *UnicodeSteganographyAnalyzer {
	return &UnicodeSteganographyAnalyzer{}
}

func (a *UnicodeSteganographyAnalyzer) Name() string {
	return "unicode-steganography"
}

type invisibleCharCounts struct {
	varSelSup  int // Variation Selectors Supplement: U+E0100-U+E01EF
	varSel     int // Standard Variation Selectors: U+FE00-U+FE0F
	tagChar    int // Tag characters: U+E0001-U+E007F
	annotation int // Interlinear annotation: U+FFF9-U+FFFB
	invisible  int
	visible    int
}

func countInvisibleChars(content string) invisibleCharCounts {
	var c invisibleCharCounts
	for _, r := range content {
		switch {
		case r >= 0xE0100 && r <= 0xE01EF:
			c.varSelSup++
			c.invisible++
		case r >= 0xFE00 && r <= 0xFE0F:
			c.varSel++
			c.invisible++
		case r >= 0xE0001 && r <= 0xE007F:
			c.tagChar++
			c.invisible++
		case r >= 0xFFF9 && r <= 0xFFFB:
			c.annotation++
			c.invisible++
		default:
			if r > 0x1F && r != 0x7F {
				c.visible++
			}
		}
	}
	return c
}

func (a *UnicodeSteganographyAnalyzer) scanContent(content, filename string) []Finding {
	c := countInvisibleChars(content)
	var findings []Finding

	findings = append(findings, a.checkVariationSelectors(c, filename)...)
	findings = append(findings, a.checkTagChars(c, filename)...)
	findings = append(findings, a.checkByteRatio(c, content, filename)...)
	findings = append(findings, a.checkAnnotations(c, filename)...)
	findings = append(findings, a.checkInvisibleDensity(c, filename)...)
	findings = append(findings, a.checkStegLibrary(content, filename)...)

	return findings
}

func (a *UnicodeSteganographyAnalyzer) checkVariationSelectors(c invisibleCharCounts, filename string) []Finding {
	var findings []Finding
	if c.varSelSup > 0 {
		findings = append(findings, Finding{
			Analyzer: a.Name(),
			Title:    fmt.Sprintf("Unicode variation selector steganography (%d chars)", c.varSelSup),
			Description: fmt.Sprintf("File %q contains %d Variation Selectors Supplement characters (U+E0100-U+E01EF). "+
				"These invisible Unicode characters were used in the os-info-checker-es6 attack to embed a hidden "+
				"base64 payload that resolved to a Google Calendar C2 dropper.", filename, c.varSelSup),
			Severity: SeverityCritical,
			ExploitExample: "Unicode steganography attack (os-info-checker-es6, May 2025):\n" +
				"    1. Invisible variation selectors appended to visible source characters\n" +
				"    2. Decoder extracts binary data from the selector sequence\n" +
				"    3. Decoded payload = base64 → Google Calendar URL → C2 command\n" +
				"    4. Code appears completely clean in any text editor or diff viewer",
			Remediation: "Strip all variation selector characters and decode the hidden payload. This is almost certainly malicious.",
		})
	}
	if c.varSel > 5 {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       fmt.Sprintf("Variation selector characters in code (%d chars)", c.varSel),
			Description: fmt.Sprintf("File %q contains %d variation selector characters (U+FE00-U+FE0F). These are normally used in emoji sequences but are suspicious in JavaScript source code.", filename, c.varSel),
			Severity:    SeverityHigh,
			Remediation: "Inspect the file for hidden data encoded in variation selector sequences.",
		})
	}
	return findings
}

func (a *UnicodeSteganographyAnalyzer) checkTagChars(c invisibleCharCounts, filename string) []Finding {
	if c.tagChar == 0 {
		return nil
	}
	return []Finding{{
		Analyzer:    a.Name(),
		Title:       fmt.Sprintf("Unicode tag characters detected (%d chars)", c.tagChar),
		Description: fmt.Sprintf("File %q contains %d Unicode tag characters (U+E0001-U+E007F). These invisible characters can encode arbitrary ASCII data and have no legitimate use in JavaScript.", filename, c.tagChar),
		Severity:    SeverityCritical,
		Remediation: "Extract the tag character sequence and decode it (each tag char maps to an ASCII char by subtracting 0xE0000).",
	}}
}

func (a *UnicodeSteganographyAnalyzer) checkByteRatio(c invisibleCharCounts, content, filename string) []Finding {
	if c.visible <= 100 || c.invisible == 0 {
		return nil
	}
	byteCount := len(content)
	runeCount := utf8.RuneCountInString(content)
	if byteCount <= runeCount*2 {
		return nil
	}
	return []Finding{{
		Analyzer:    a.Name(),
		Title:       "Byte-to-character ratio anomaly",
		Description: fmt.Sprintf("File %q has %d bytes but only %d visible characters. The excess bytes indicate hidden multibyte Unicode content.", filename, byteCount, c.visible),
		Severity:    SeverityHigh,
		Remediation: "Inspect the file at the byte level for hidden Unicode sequences.",
	}}
}

func (a *UnicodeSteganographyAnalyzer) checkAnnotations(c invisibleCharCounts, filename string) []Finding {
	if c.annotation == 0 {
		return nil
	}
	return []Finding{{
		Analyzer:    a.Name(),
		Title:       fmt.Sprintf("Interlinear annotation characters (%d chars)", c.annotation),
		Description: fmt.Sprintf("File %q contains %d interlinear annotation characters (U+FFF9-U+FFFB). These have no legitimate use in JavaScript and can hide text.", filename, c.annotation),
		Severity:    SeverityHigh,
		Remediation: "Remove interlinear annotation characters and inspect surrounding content.",
	}}
}

func (a *UnicodeSteganographyAnalyzer) checkInvisibleDensity(c invisibleCharCounts, filename string) []Finding {
	if c.invisible <= 20 || c.visible == 0 {
		return nil
	}
	ratio := float64(c.invisible) / float64(c.visible)
	if ratio <= 0.01 || c.varSelSup > 0 || c.tagChar > 0 {
		return nil
	}
	return []Finding{{
		Analyzer:    a.Name(),
		Title:       fmt.Sprintf("High invisible Unicode density (%.1f%%)", ratio*100),
		Description: fmt.Sprintf("File %q contains %d invisible Unicode characters among %d visible characters. This density is abnormal for source code.", filename, c.invisible, c.visible),
		Severity:    SeverityHigh,
		Remediation: "Examine the file with a hex editor to identify and decode hidden content.",
	}}
}

func (a *UnicodeSteganographyAnalyzer) checkStegLibrary(content, filename string) []Finding {
	if !strings.Contains(content, "steganography") && !strings.Contains(content, "steg.decode") {
		return nil
	}
	return []Finding{{
		Analyzer:    a.Name(),
		Title:       "Steganography library reference",
		Description: fmt.Sprintf("File %q references steganography functionality, which can be used to hide payloads in images or data.", filename),
		Severity:    SeverityHigh,
		Remediation: "Investigate what data is being decoded from steganographic sources.",
	}}
}
