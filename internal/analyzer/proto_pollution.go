package analyzer

import (
	"fmt"
	"regexp"
	"strings"
)

// ProtoPollutionAnalyzer detects prototype pollution vulnerabilities and
// attacks in JavaScript code. Prototype pollution can escalate to RCE in
// Node.js applications.
// Based on USENIX Security 2022 "Silent Spring" and BlackHat 2023 prototype pollution research.
type ProtoPollutionAnalyzer struct{}

func NewProtoPollutionAnalyzer() *ProtoPollutionAnalyzer {
	return &ProtoPollutionAnalyzer{}
}

func (a *ProtoPollutionAnalyzer) Name() string {
	return "proto-pollution"
}

var (
	// Direct __proto__ access
	protoAccessPattern = regexp.MustCompile(`__proto__`)

	// constructor.prototype access chain
	constructorProtoPattern = regexp.MustCompile(`(?i)constructor\s*[\[.]\s*(?:['"]?\s*prototype|['"]prototype['"])`)

	// Unsafe recursive merge/extend functions (target[key] = source[key] in a loop)
	unsafeMergePattern = regexp.MustCompile(`(?i)(?:function\s+\w*(?:merge|extend|assign|mixin|defaults)\w*|(?:merge|extend|assign|mixin|defaults)\s*(?:=|:)\s*(?:function|\())`)

	// Object.defineProperty on prototype
	defineOnProtoPattern = regexp.MustCompile(`Object\.defineProperty\s*\(\s*(?:Object|[A-Z]\w*)\.prototype`)

	// Dynamic property assignment with bracket notation in loop
	dynamicPropInLoopPattern = regexp.MustCompile(`(?:for\s*\(|\.(?:keys|entries|forEach)\s*\()`)
)

func (a *ProtoPollutionAnalyzer) scanContent(content string, filename string) []Finding {
	var findings []Finding

	// Direct __proto__ manipulation
	if protoAccessPattern.MatchString(content) {
		severity := SeverityHigh
		if strings.Contains(content, "target[") || strings.Contains(content, "merge") {
			severity = SeverityCritical
		}
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Prototype pollution: __proto__ access",
			Description: fmt.Sprintf("File %q accesses __proto__ which can be used for prototype pollution attacks. If user-controlled data reaches this code path, it can modify Object.prototype.", filename),
			Severity:    severity,
			ExploitExample: "Prototype pollution via __proto__:\n" +
				"    merge({}, JSON.parse('{\"__proto__\":{\"isAdmin\":true}}'));\n" +
				"    // Now ALL objects have isAdmin === true\n" +
				"    console.log({}.isAdmin); // true",
			Remediation: "Use Object.create(null) for dictionary objects. Add __proto__ to property blocklist in merge functions.",
		})
	}

	// constructor.prototype manipulation
	if constructorProtoPattern.MatchString(content) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Prototype pollution via constructor.prototype",
			Description: fmt.Sprintf("File %q accesses constructor.prototype which is an alternative path for prototype pollution that bypasses __proto__ filters.", filename),
			Severity:    SeverityCritical,
			ExploitExample: "Bypassing __proto__ filter:\n" +
				"    // Even if __proto__ is blocked:\n" +
				"    obj.constructor.prototype.isAdmin = true;\n" +
				"    // Or via bracket notation:\n" +
				"    obj['constructor']['prototype']['isAdmin'] = true;",
			Remediation: "Block both __proto__ and constructor keys in merge/assignment functions. Use Object.create(null).",
		})
	}

	// Unsafe recursive merge function
	if unsafeMergePattern.MatchString(content) {
		hasDynamicAssign := strings.Contains(content, "target[key]") || strings.Contains(content, "target[k]") ||
			(dynamicPropInLoopPattern.MatchString(content) && strings.Contains(content, "typeof") && strings.Contains(content, "object"))
		if hasDynamicAssign {
			findings = append(findings, Finding{
				Analyzer:    a.Name(),
				Title:       "Unsafe recursive merge susceptible to prototype pollution",
				Description: fmt.Sprintf("File %q implements a recursive merge/extend that assigns properties dynamically without checking for __proto__ or constructor. This is the most common source of prototype pollution.", filename),
				Severity:    SeverityHigh,
				ExploitExample: "Unsafe merge:\n" +
					"    function deepMerge(target, source) {\n" +
					"        for (key in source) target[key] = source[key]; // UNSAFE\n" +
					"    }\n" +
					"    deepMerge({}, {__proto__: {isAdmin: true}});",
				Remediation: "Add key validation: skip '__proto__', 'constructor', 'prototype'. Use Object.hasOwn() instead of 'in'.",
			})
		}
	}

	// Object.defineProperty on prototype
	if defineOnProtoPattern.MatchString(content) {
		findings = append(findings, Finding{
			Analyzer:    a.Name(),
			Title:       "Object.defineProperty on prototype chain",
			Description: fmt.Sprintf("File %q uses Object.defineProperty on a prototype object, which modifies the property for all instances.", filename),
			Severity:    SeverityCritical,
			ExploitExample: "Prototype modification via defineProperty:\n" +
				"    Object.defineProperty(Object.prototype, 'polluted', {\n" +
				"        value: 'yes'\n" +
				"    });\n" +
				"    // Now every object has 'polluted' property",
			Remediation: "Investigate why defineProperty is called on a prototype. This is extremely suspicious in an npm package.",
		})
	}

	return findings
}
