import { motion } from 'framer-motion';
import { Terminal, ShieldAlert, Cpu, Brain } from 'lucide-react';

export function Hero() {
  return (
    <section className="relative pt-32 pb-20 overflow-hidden">
      {/* Background decoration */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-[500px] bg-blue-500/10 blur-[120px] rounded-full -z-10" />
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20 mb-6">
              Advanced npm Security Auditor
            </span>
            <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight mb-6 bg-gradient-to-b from-white to-neutral-500 bg-clip-text text-transparent">
              Deep Forensic Analysis <br /> for the npm Supply Chain
            </h1>
            <p className="text-xl text-neutral-400 max-w-3xl mx-auto mb-10">
              Detect malware, backdoors, and supply chain attacks before they reach production. 
              Checking beyond known CVEs with 40+ research-backed security analyzers.
            </p>
          </motion.div>

          <motion.div 
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16"
          >
            <a 
              href="#installation"
              className="w-full sm:w-auto px-8 py-4 bg-white text-neutral-950 rounded-xl font-bold text-lg hover:bg-neutral-200 transition-all flex items-center justify-center gap-2"
            >
              Get Started
            </a>
            <div className="w-full sm:w-auto px-8 py-4 bg-neutral-900 text-white rounded-xl font-mono text-lg border border-neutral-800 flex items-center justify-center gap-3">
              <span className="text-blue-500">$</span>
              <span>auditter express</span>
            </div>
          </motion.div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl mx-auto">
            {[
              { icon: ShieldAlert, label: "40+ Analyzers" },
              { icon: Brain, label: "AI Summaries" },
              { icon: Cpu, label: "Behavior Sandbox" },
              { icon: Terminal, label: "12 Languages" }
            ].map((item, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: 0.4 + i * 0.1 }}
                className="p-4 rounded-2xl bg-neutral-900/50 border border-neutral-800 flex flex-col items-center gap-2"
              >
                <item.icon className="w-6 h-6 text-blue-500" />
                <span className="text-sm font-medium text-neutral-300">{item.label}</span>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
