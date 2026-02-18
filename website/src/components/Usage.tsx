import { motion } from 'framer-motion';
import { Terminal, Settings, Database, FileCode } from 'lucide-react';

const flags = [
  { flag: '--project (-p)', desc: 'Path to package.json or package-lock.json', default: '-' },
  { flag: '--node-modules', desc: 'Audit all dependencies from node_modules/', default: 'false' },
  { flag: '--format', desc: 'Output: terminal, json, markdown, html, csv, pdf', default: 'terminal' },
  { flag: '--json', desc: 'Alias for --format json', default: 'false' },
  { flag: '--severity (-s)', desc: 'Minimum severity: low, medium, high, critical', default: 'low' },
  { flag: '--lang', desc: 'Report language (en, de, fr, es, it, pt, jp, zh, ru)', default: 'en' },
  { flag: '--interactive (-i)', desc: 'Launch TUI mode (Bubble Tea)', default: 'false' },
  { flag: '--ai-summary', desc: 'Generate AI analysis via Gemini CLI', default: 'false' },
  { flag: '--no-sandbox', desc: 'Disable dynamic analysis', default: 'false' },
  { flag: '--concurrency (-c)', desc: 'Max concurrent package audits', default: '5' },
  { flag: '--timeout', desc: 'Timeout per package (seconds)', default: '180' },
  { flag: '--registry (-r)', desc: 'Custom npm registry URL', default: 'npmjs.org' },
  { flag: '--output (-o)', desc: 'Write report to file', default: 'stdout' },
  { flag: '--verbose (-v)', desc: 'Show all individual findings', default: 'false' },
];

export function Usage() {
  return (
    <section id="usage" className="py-24 bg-neutral-900/30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-5xl font-bold mb-4">Command Line Usage</h2>
          <p className="text-neutral-400 text-lg max-w-2xl mx-auto">
            Flexible configuration for any environment, from local development to enterprise CI/CD pipelines.
          </p>
        </div>

        <div className="grid lg:grid-cols-2 gap-12">
          {/* Flags Table */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="bg-neutral-900 border border-neutral-800 rounded-3xl overflow-hidden"
          >
            <div className="p-6 border-b border-neutral-800 bg-neutral-900/50 flex items-center gap-3">
              <Terminal className="w-5 h-5 text-blue-500" />
              <h3 className="font-bold">Flags Reference</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="bg-neutral-950/50 text-neutral-400">
                    <th className="p-4 font-medium">Flag</th>
                    <th className="p-4 font-medium">Description</th>
                    <th className="p-4 font-medium text-right">Default</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-neutral-800">
                  {flags.map((item, i) => (
                    <tr key={i} className="hover:bg-neutral-800/30 transition-colors">
                      <td className="p-4 font-mono text-blue-400 whitespace-nowrap">{item.flag}</td>
                      <td className="p-4 text-neutral-300">{item.desc}</td>
                      <td className="p-4 text-neutral-500 text-right font-mono">{item.default}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </motion.div>

          {/* Examples & Config */}
          <div className="space-y-8">
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.1 }}
              className="bg-neutral-900 border border-neutral-800 rounded-3xl p-8"
            >
              <div className="flex items-center gap-3 mb-6">
                <FileCode className="w-6 h-6 text-green-500" />
                <h3 className="text-xl font-bold">Common Examples</h3>
              </div>
              <div className="space-y-4 font-mono text-sm">
                <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800">
                  <div className="text-neutral-500 mb-2"># Audit project dependencies</div>
                  <div className="text-blue-400">auditter -p package.json</div>
                </div>
                <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800">
                  <div className="text-neutral-500 mb-2"># JSON output for CI pipeline</div>
                  <div className="text-blue-400">auditter -p package-lock.json --json &gt; audit.json</div>
                </div>
                <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800">
                  <div className="text-neutral-500 mb-2"># Full PDF report with AI summary</div>
                  <div className="text-blue-400">auditter --format pdf -o report.pdf --ai-summary</div>
                </div>
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, x: 20 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.2 }}
              className="bg-neutral-900 border border-neutral-800 rounded-3xl p-8"
            >
              <div className="flex items-center gap-3 mb-6">
                <Settings className="w-6 h-6 text-purple-500" />
                <h3 className="text-xl font-bold">Configuration</h3>
              </div>
              <p className="text-neutral-400 mb-4">
                Configure via <code className="bg-neutral-800 px-1.5 py-0.5 rounded text-neutral-300">.auditter.yaml</code> or environment variables.
              </p>
              <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800 font-mono text-sm text-neutral-400">
                <div>AUDITTER_REGISTRY=https://registry.npmjs.org</div>
                <div>AUDITTER_FORMAT=json</div>
                <div>AUDITTER_SEVERITY=high</div>
              </div>
            </motion.div>
            
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.3 }}
              className="bg-neutral-900 border border-neutral-800 rounded-3xl p-8"
            >
               <div className="flex items-center gap-3 mb-6">
                <Database className="w-6 h-6 text-orange-500" />
                <h3 className="text-xl font-bold">Threat Intelligence</h3>
              </div>
               <p className="text-neutral-400 mb-4">
                Auditter automatically updates its local intelligence cache every 24 hours from 25+ sources.
              </p>
               <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800 font-mono text-sm text-blue-400">
                auditter update-intel
              </div>
            </motion.div>

          </div>
        </div>
      </div>
    </section>
  );
}
