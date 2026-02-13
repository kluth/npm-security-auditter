package analyzer

import (
	"strings"
	"testing"
)

func TestUnicodeSteganography_VariationSelectorSupplement(t *testing.T) {
	a := NewUnicodeSteganographyAnalyzer()
	// Embed U+E0100 (Variation Selector-17) characters
	content := "const a = 'hello'\U000E0100\U000E0101\U000E0102;\nconsole.log(a);"
	findings := a.scanContent(content, "index.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "variation selector steganography") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected critical severity, got %d", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected to detect variation selector supplement steganography")
	}
}

func TestUnicodeSteganography_TagCharacters(t *testing.T) {
	a := NewUnicodeSteganographyAnalyzer()
	// U+E0001 (Language Tag) + U+E0041-U+E005A = hidden ASCII
	content := "module.exports = {};\U000E0001\U000E0041\U000E0042\U000E0043"
	findings := a.scanContent(content, "lib.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "tag characters") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected critical severity, got %d", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected to detect Unicode tag characters")
	}
}

func TestUnicodeSteganography_StandardVariationSelectors(t *testing.T) {
	a := NewUnicodeSteganographyAnalyzer()
	// 6 standard variation selectors (U+FE00-U+FE0F) - threshold is >5
	content := "const x = 1;\uFE00\uFE01\uFE02\uFE03\uFE04\uFE05\nreturn x;"
	findings := a.scanContent(content, "code.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Variation selector characters") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect standard variation selectors above threshold")
	}
}

func TestUnicodeSteganography_InterlinearAnnotation(t *testing.T) {
	a := NewUnicodeSteganographyAnalyzer()
	// U+FFF9 = Interlinear Annotation Anchor
	content := "const data = 'test';\uFFF9hidden\uFFFBvisible"
	findings := a.scanContent(content, "anno.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Interlinear annotation") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect interlinear annotation characters")
	}
}

func TestUnicodeSteganography_SteganographyLibRef(t *testing.T) {
	a := NewUnicodeSteganographyAnalyzer()
	content := `
const steg = require('steganography');
const hidden = steg.decode(imageBuffer);
eval(hidden);
`
	findings := a.scanContent(content, "decode.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Steganography library") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect steganography library reference")
	}
}

func TestUnicodeSteganography_CleanCode(t *testing.T) {
	a := NewUnicodeSteganographyAnalyzer()
	content := `
const express = require('express');
const app = express();
app.get('/', (req, res) => res.send('Hello World'));
app.listen(3000);
`
	findings := a.scanContent(content, "server.js")
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity finding in clean code: %s", f.Title)
		}
	}
}
