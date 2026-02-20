import { motion } from 'framer-motion';
import { Cpu, Terminal, Shield, List } from 'lucide-react';
import { TerminalWindow } from './ui/TerminalWindow';

export function Mcp() {
  return (
    <section id="mcp" className="py-24">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col lg:flex-row gap-16 items-center">
          <div className="lg:w-1/2">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-500/10 text-purple-400 text-xs font-bold border border-purple-500/20 mb-6 uppercase tracking-wider">
              <Cpu className="w-3 h-3" />
              AI-Native Security
            </div>
            <h2 className="text-3xl md:text-5xl font-bold mb-6">Model Context Protocol</h2>
            <p className="text-neutral-400 text-lg mb-8 leading-relaxed">
              Auditter implements the <a href="https://modelcontextprotocol.io" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">Model Context Protocol (MCP)</a>, 
              turning it into a powerful tool for AI assistants like Claude Desktop. LLMs can now directly audit 
              your supply chain and local projects with precision.
            </p>

            <div className="space-y-6">
              <div className="flex gap-4">
                <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center shrink-0">
                  <Shield className="w-5 h-5 text-blue-500" />
                </div>
                <div>
                  <h4 className="font-bold mb-1">audit_package</h4>
                  <p className="text-sm text-neutral-400">LLMs can perform deep scans of specific npm packages by name and version.</p>
                </div>
              </div>
              <div className="flex gap-4">
                <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center shrink-0">
                  <Terminal className="w-5 h-5 text-green-500" />
                </div>
                <div>
                  <h4 className="font-bold mb-1">audit_project</h4>
                  <p className="text-sm text-neutral-400">AI agents can audit your entire local project by scanning package.json and lockfiles.</p>
                </div>
              </div>
              <div className="flex gap-4">
                <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center shrink-0">
                  <List className="w-5 h-5 text-purple-500" />
                </div>
                <div>
                  <h4 className="font-bold mb-1">list_analyzers</h4>
                  <p className="text-sm text-neutral-400">Allows AI to discover and understand the 40+ specialized forensic security checks.</p>
                </div>
              </div>
            </div>
          </div>

          <div className="lg:w-1/2 w-full">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              className="space-y-6"
            >
              <TerminalWindow title="claude_desktop_config.json">
                <pre className="text-xs text-neutral-400 leading-relaxed">
{`{
  "mcpServers": {
    "auditter": {
      "command": "auditter",
      "args": ["mcp"]
    }
  }
}`}
                </pre>
              </TerminalWindow>

              <div className="p-6 rounded-2xl bg-neutral-900 border border-neutral-800">
                <h4 className="text-sm font-bold mb-4 text-neutral-300 uppercase tracking-widest">Claude Tool Call</h4>
                <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800 font-mono text-xs">
                  <div className="text-purple-400">User:</div>
                  <div className="text-neutral-300 mb-2 italic">"Audit the 'express' package for any security risks."</div>
                  <div className="text-blue-400">Claude:</div>
                  <div className="text-neutral-500">Calling tool: audit_package(&#123;"package_name": "express"&#125;)...</div>
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    </section>
  );
}
