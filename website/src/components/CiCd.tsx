import { motion } from 'framer-motion';
import { GitBranch, Box, CheckCircle } from 'lucide-react';
import { useState } from 'react';

const examples = {
  github: {
    title: "GitHub Actions",
    code: `name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Auditter
        run: |
          curl -LO https://github.com/kluth/npm-security-auditter/releases/latest/download/auditter_2.1.0_linux_amd64.tar.gz
          tar xzf auditter_2.1.0_linux_amd64.tar.gz

      - name: Run Security Audit
        run: ./auditter -p package-lock.json -s high --json > audit.json

      - name: Check for Critical Findings
        run: |
          if jq -e '.reports[].results[].findings[] | select(.severity == "CRITICAL")' audit.json > /dev/null 2>&1; then
            echo "::error::Critical security findings detected"
            exit 1
          fi`
  },
  gitlab: {
    title: "GitLab CI",
    code: `security_audit:
  image: golang:1.23
  script:
    - go install github.com/kluth/npm-security-auditter/cmd/auditter@latest
    - auditter -p package-lock.json -s high --json > audit.json
  artifacts:
    paths:
      - audit.json
    expire_in: 1 week`
  },
  shell: {
    title: "Shell / Local Hook",
    code: `# Fail if any critical findings are present
auditter -p package.json -s critical --json | jq -e '.reports | length == 0'

# Run as a pre-commit hook
#!/bin/sh
if ! auditter -p package.json -s critical; then
    echo "Security audit failed. Commit rejected."
    exit 1
fi`
  }
};

export function CiCd() {
  const [activeTab, setActiveTab] = useState<'github' | 'gitlab' | 'shell'>('github');

  return (
    <section id="cicd" className="py-24">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row gap-16 items-start">
          <div className="md:w-1/3">
            <h2 className="text-4xl font-bold mb-6">Seamless CI/CD Integration</h2>
            <p className="text-neutral-400 text-lg mb-8">
              Block supply chain attacks before they merge. Auditter integrates natively with GitHub Actions, GitLab CI, and other pipelines.
            </p>
            
            <div className="space-y-6">
              <div className="flex gap-4 items-start">
                <div className="p-3 bg-green-500/10 rounded-xl border border-green-500/20">
                  <CheckCircle className="w-6 h-6 text-green-500" />
                </div>
                <div>
                  <h3 className="font-bold text-white mb-1">Gatekeeper Policy</h3>
                  <p className="text-sm text-neutral-400">Automatically fail builds when critical vulnerabilities or malware patterns are detected.</p>
                </div>
              </div>
              
              <div className="flex gap-4 items-start">
                <div className="p-3 bg-purple-500/10 rounded-xl border border-purple-500/20">
                  <Box className="w-6 h-6 text-purple-500" />
                </div>
                <div>
                  <h3 className="font-bold text-white mb-1">Artifact Generation</h3>
                  <p className="text-sm text-neutral-400">Generate JSON or SARIF reports for dashboard integration and compliance tracking.</p>
                </div>
              </div>
            </div>
          </div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="md:w-2/3 w-full bg-neutral-900 border border-neutral-800 rounded-3xl overflow-hidden shadow-2xl"
          >
            <div className="flex border-b border-neutral-800 bg-neutral-950/50">
              {(Object.keys(examples) as Array<keyof typeof examples>).map((key) => (
                <button
                  key={key}
                  onClick={() => setActiveTab(key)}
                  className={`px-6 py-4 text-sm font-medium transition-colors flex items-center gap-2 border-b-2 ${
                    activeTab === key
                      ? 'border-blue-500 text-white bg-neutral-900'
                      : 'border-transparent text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/50'
                  }`}
                >
                  <GitBranch className="w-4 h-4" />
                  {examples[key].title}
                </button>
              ))}
            </div>
            
            <div className="p-0 overflow-x-auto">
              <pre className="p-6 text-sm font-mono leading-relaxed text-neutral-300">
                <code>{examples[activeTab].code}</code>
              </pre>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
