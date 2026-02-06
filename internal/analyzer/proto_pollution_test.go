package analyzer

import (
	"strings"
	"testing"
)

func TestProtoPollution_DirectProtoAccess(t *testing.T) {
	a := NewProtoPollutionAnalyzer()
	content := `
function merge(target, source) {
	for (let key in source) {
		if (key === '__proto__') {
			target[key] = source[key];
		}
	}
}
`
	findings := a.scanContent(content, "merge.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "proto") || strings.Contains(f.Title, "Proto") || strings.Contains(f.Title, "pollution") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect __proto__ access")
	}
}

func TestProtoPollution_ConstructorPrototype(t *testing.T) {
	a := NewProtoPollutionAnalyzer()
	content := `
obj.constructor.prototype.isAdmin = true;
obj['constructor']['prototype']['admin'] = true;
`
	findings := a.scanContent(content, "exploit.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "constructor") || strings.Contains(f.Title, "Constructor") || strings.Contains(f.Title, "proto") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect constructor.prototype pollution")
	}
}

func TestProtoPollution_RecursiveMerge(t *testing.T) {
	a := NewProtoPollutionAnalyzer()
	content := `
function deepMerge(target, source) {
	for (const key of Object.keys(source)) {
		if (typeof source[key] === 'object' && source[key] !== null) {
			if (!target[key]) target[key] = {};
			deepMerge(target[key], source[key]);
		} else {
			target[key] = source[key];
		}
	}
	return target;
}
`
	findings := a.scanContent(content, "deep_merge.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "merge") || strings.Contains(f.Title, "Merge") || strings.Contains(f.Title, "recursive") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect unsafe recursive merge")
	}
}

func TestProtoPollution_ObjectDefineProperty(t *testing.T) {
	a := NewProtoPollutionAnalyzer()
	content := `
Object.defineProperty(Object.prototype, 'polluted', {
	value: 'yes',
	writable: true,
	enumerable: false,
});
`
	findings := a.scanContent(content, "define.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Object.prototype") || strings.Contains(f.Title, "defineProperty") || strings.Contains(f.Title, "proto") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect Object.defineProperty on prototype")
	}
}

func TestProtoPollution_CleanCode(t *testing.T) {
	a := NewProtoPollutionAnalyzer()
	content := `
const obj = { name: 'test', value: 42 };
const copy = Object.assign({}, obj);
console.log(copy.name);
`
	findings := a.scanContent(content, "clean.js")
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity in clean code: %s", f.Title)
		}
	}
}
