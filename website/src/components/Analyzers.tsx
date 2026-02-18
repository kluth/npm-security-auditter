import { motion } from 'framer-motion';

const analyzerCategories = [
  {
    title: "Supply Chain & Metadata",
    items: ["Typosquatting Detection", "Manifest Confusion", "Star-jacking Detection", "Version Anomalies", "Community Trust Scoring"]
  },
  {
    title: "Deep Code Analysis",
    items: ["AST Deep Scanning", "Taint Analysis", "Multi-layer Obfuscation", "Anti-debug Evasion", "Prototype Pollution"]
  },
  {
    title: "Malware Patterns",
    items: ["Multi-stage Loaders", "Time-bomb Detection", "Crypto Theft Detection", "Phishing Infrastructure", "Exfiltration Chains"]
  },
  {
    title: "Build & Integrity",
    items: ["SLSA Provenance", "Code Signing Verification", "Reproducible Builds", "OpenSSF Scorecards", "Lockfile Integrity"]
  }
];

export function Analyzers() {
  return (
    <section id="analyzers" className="py-24">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row gap-16 items-start">
          <div className="md:w-1/3 sticky top-32">
            <h2 className="text-4xl font-bold mb-6">40+ Forensic Analyzers</h2>
            <p className="text-neutral-400 text-lg mb-8">
              Each analyzer is research-backed and tested against real-world malware samples from major supply chain attacks.
            </p>
            <div className="flex flex-wrap gap-2">
              <span className="px-3 py-1 rounded-full bg-blue-500/10 text-blue-400 text-xs font-bold border border-blue-500/20">USENIX SECURITY</span>
              <span className="px-3 py-1 rounded-full bg-blue-500/10 text-blue-400 text-xs font-bold border border-blue-500/20">BLACKHAT</span>
              <span className="px-3 py-1 rounded-full bg-blue-500/10 text-blue-400 text-xs font-bold border border-blue-500/20">DEF CON</span>
            </div>
          </div>

          <div className="md:w-2/3 grid sm:grid-cols-2 gap-6">
            {analyzerCategories.map((category, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: 20 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: i * 0.1 }}
                className="p-6 rounded-2xl bg-neutral-900 border border-neutral-800"
              >
                <h3 className="text-lg font-bold mb-4 text-blue-500">{category.title}</h3>
                <ul className="space-y-3">
                  {category.items.map((item, j) => (
                    <li key={j} className="flex items-center gap-2 text-neutral-400">
                      <div className="w-1.5 h-1.5 rounded-full bg-neutral-700" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
