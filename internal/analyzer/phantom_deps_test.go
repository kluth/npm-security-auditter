package analyzer

import (
	"strings"
	"testing"
)

func TestPhantomDepsAnalyzer_UndeclaredRequire(t *testing.T) {
	a := NewPhantomDepsAnalyzer()
	// child_process is a Node builtin but combined with network = suspicious
	content := `
const cp = require('child_process');
const http = require('http');
const evil = require('totally-unknown-module');
`
	deps := map[string]string{"lodash": "^4.0.0"}
	findings := a.scanContentWithDeps(content, "index.js", deps)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Phantom") || strings.Contains(f.Title, "phantom") || strings.Contains(f.Title, "undeclared") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect phantom/undeclared dependency")
	}
}

func TestPhantomDepsAnalyzer_DangerousBuiltins(t *testing.T) {
	a := NewPhantomDepsAnalyzer()
	content := `
const cp = require('child_process');
const net = require('net');
const dgram = require('dgram');
`
	deps := map[string]string{}
	findings := a.scanContentWithDeps(content, "index.js", deps)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "dangerous") || strings.Contains(f.Title, "Dangerous") || strings.Contains(f.Title, "builtin") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to flag multiple dangerous builtins")
	}
}

func TestPhantomDepsAnalyzer_NormalRequires(t *testing.T) {
	a := NewPhantomDepsAnalyzer()
	content := `
const lodash = require('lodash');
const express = require('express');
const path = require('path');
`
	deps := map[string]string{"lodash": "^4.0.0", "express": "^5.0.0"}
	findings := a.scanContentWithDeps(content, "index.js", deps)

	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity for normal requires: %s", f.Title)
		}
	}
}
