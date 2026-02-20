import { TerminalWindow } from './ui/TerminalWindow';
import { motion } from 'framer-motion';

export function TuiShowcase() {
  return (
    <section id="tui" className="py-24 bg-neutral-900/30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-5xl font-bold mb-4">Interactive TUI Dashboard</h2>
          <p className="text-neutral-400 text-lg max-w-2xl mx-auto">
            A powerful terminal user interface for seamless auditing, configuration, and result analysis.
          </p>
        </div>

        <div className="grid lg:grid-cols-2 gap-8 items-start">
          <div className="space-y-8">
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
            >
              <h3 className="text-2xl font-bold mb-4 text-blue-400">Dashboard & Navigation</h3>
              <p className="text-neutral-400 mb-4">
                Navigate effortlessly between project audits, package scans, and settings. 
                The new dashboard provides a bird's-eye view of your security posture.
              </p>
              <TerminalWindow title="auditter - dashboard">
                <pre className="text-xs leading-relaxed">
{`┌──────────────────────────────┐┌──────────────────────────────────────────────────┐
│  npm-security-auditter       ││                                                  │
│                              ││            No audit results yet.                 │
│  > Audit Package             ││      Select an option from the menu to start.    │
│    Audit Project             ││                                                  │
│    Audit node_modules        ││                                                  │
│    Audit Top Repos           ││                                                  │
│    Settings                  ││                                                  │
│    Threat Intelligence       ││                                                  │
│    Results                   ││                                                  │
│                              ││                                                  │
│                              ││                                                  │
│                              ││                                                  │
└──────────────────────────────┘└──────────────────────────────────────────────────┘
  tab switch pane • ↑/↓ navigate • enter select/detail • s save • q quit`}
                </pre>
              </TerminalWindow>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, x: -20 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ delay: 0.2 }}
            >
              <h3 className="text-2xl font-bold mb-4 text-blue-400">Top Repos Audit</h3>
              <p className="text-neutral-400 mb-4">
                Discover the most secure packages in any category. Compare top GitHub repositories 
                instantly to make informed architectural decisions.
              </p>
              <TerminalWindow title="auditter - top repos">
                 <pre className="text-xs leading-relaxed">
{`  Top Secure Packages: web-framework

  RANK PACKAGE                    RISK SCORE   VERDICT                        
  ──── ────────────────────────── ──────────── ──────────────────────────────
  1.  express                     20/100       ✅ Low Risk                    
  2.  fastify                     25/100       ✅ Low Risk                    
  3.  koa                         30/100       ⚠️ Medium Risk                 
  4.  hapi                        35/100       ⚠️ Medium Risk                 
  5.  nest.js                     40/100       ⚠️ Medium Risk                 
  ...

  Audited at 2024-05-20T10:00:00Z`}
                </pre>
              </TerminalWindow>
            </motion.div>
          </div>

          <div className="space-y-8 lg:mt-12">
            <motion.div
               initial={{ opacity: 0, x: 20 }}
               whileInView={{ opacity: 1, x: 0 }}
               viewport={{ once: true }}
               transition={{ delay: 0.1 }}
            >
              <h3 className="text-2xl font-bold mb-4 text-blue-400">Detailed Findings</h3>
              <p className="text-neutral-400 mb-4">
                Drill down into specific vulnerabilities. View code snippets, severity levels, 
                and remediation advice directly in your terminal.
              </p>
              <TerminalWindow title="auditter - findings">
                <pre className="text-xs leading-relaxed">
{`┌────────────────────────────────┐┌──────────────────────────────────────────────────┐
│  Audit Results                 ││  Finding Detail  Finding 1 of 5                  │
│                                ││                                                  │
│  Duration: 2.5s                ││  Title:     Prototype Pollution in merge()       │
│  Risk Score: 85/100            ││  Severity:  CRITICAL                             │
│  Findings: 5 total             ││  Analyzer:  AST Deep Scanning                    │
│   1 critical  2 high           ││  Location:  lib/utils.js:42                      │
│                                ││                                                  │
│  > [CRITICAL] Proto Pollution  ││  Code snippet:                                   │
│    [HIGH] Install Script       ││    function merge(target, source) {              │
│    [HIGH] Typosquatting        ││      for (let key in source) {                   │
│    [MEDIUM] No License         ││        target[key] = source[key];                │
│    [LOW] Old Version           ││      }                                           │
│                                ││    }                                             │
└────────────────────────────────┘└──────────────────────────────────────────────────┘`}
                </pre>
              </TerminalWindow>
            </motion.div>
             <motion.div
               initial={{ opacity: 0, x: 20 }}
               whileInView={{ opacity: 1, x: 0 }}
               viewport={{ once: true }}
               transition={{ delay: 0.3 }}
            >
              <h3 className="text-2xl font-bold mb-4 text-blue-400">AI-Powered Analysis</h3>
              <p className="text-neutral-400 mb-4">
                Get instant, human-readable summaries of complex audit reports using Gemini or Claude AI 
                integration directly within the tool.
              </p>
              <TerminalWindow title="auditter - AI summary">
                <pre className="text-xs leading-relaxed text-cyan-300">
{`╔══════════════════════════════════════════════════════════════════════╗
║  AI Analysis (Claude)                                                ║
╚══════════════════════════════════════════════════════════════════════╝

VERDICT: DO NOT INSTALL - Critical prototype pollution vulnerability detected.

KEY RISKS:
- Prototype Pollution in merge() function allows arbitrary property injection.
- Suspicious preinstall script downloads binary from unknown IP.

RECOMMENDED ACTIONS:
- Use a safer alternative like 'lodash.merge' or 'deepmerge'.
- Block network access for install scripts in CI.`}
                </pre>
              </TerminalWindow>
            </motion.div>
          </div>
        </div>
      </div>
    </section>
  );
}
