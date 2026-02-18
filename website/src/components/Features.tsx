import { motion } from 'framer-motion';
import { Search, Zap, Globe, ShieldCheck, FileText } from 'lucide-react';

const features = [
  {
    icon: Search,
    title: "Beyond CVEs",
    description: "Standard audits only check for known vulnerabilities. Auditter detects zero-day threats through deep forensic analysis."
  },
  {
    icon: Zap,
    title: "Behavioral Sandbox",
    description: "Monitors network calls, filesystem changes, and process spawning in a safe, isolated environment."
  },
  {
    icon: Globe,
    title: "25+ Intel Sources",
    description: "Aggregates threat intelligence from OSV, NIST, URLhaus, Socket.dev, and various security research labs."
  },
  {
    icon: Brain,
    title: "AI Analysis",
    description: "Generates human-readable summaries of complex security findings using Google Gemini AI."
  },
  {
    icon: ShieldCheck,
    title: "Integrity Verification",
    description: "Checks SLSA provenance, code signing, and reproducible build attestations for maximum trust."
  },
  {
    icon: FileText,
    title: "Flexible Reporting",
    description: "Exports results in Terminal, JSON, Markdown, HTML, CSV, and high-quality PDF formats."
  }
];

import { Brain } from 'lucide-react';

export function Features() {
  return (
    <section id="features" className="py-24 bg-neutral-900/30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-5xl font-bold mb-4">Powerful Security Arsenal</h2>
          <p className="text-neutral-400 text-lg max-w-2xl mx-auto">
            A comprehensive suite of tools designed to protect your supply chain from every angle.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-8">
          {features.map((feature, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: i * 0.1 }}
              className="p-8 rounded-3xl bg-neutral-900 border border-neutral-800 hover:border-blue-500/50 transition-all group"
            >
              <div className="w-12 h-12 rounded-xl bg-blue-500/10 flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
                <feature.icon className="w-6 h-6 text-blue-500" />
              </div>
              <h3 className="text-xl font-bold mb-3">{feature.title}</h3>
              <p className="text-neutral-400 leading-relaxed">
                {feature.description}
              </p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
