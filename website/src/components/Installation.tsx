import React from 'react';
import { Terminal, Download, Github } from 'lucide-react';

const osOptions = [
  { 
    name: "macOS", 
    command: `curl -LO https://github.com/kluth/npm-security-auditter/releases/latest/download/auditter_v2.1.0_macOS_Universal.pkg
sudo installer -pkg auditter_v2.1.0_macOS_Universal.pkg -target /` 
  },
  { 
    name: "Debian / Ubuntu", 
    command: `curl -LO https://github.com/kluth/npm-security-auditter/releases/latest/download/auditter_2.1.0_linux_amd64.deb
sudo dpkg -i auditter_2.1.0_linux_amd64.deb` 
  },
  { 
    name: "Fedora / RHEL", 
    command: `curl -LO https://github.com/kluth/npm-security-auditter/releases/latest/download/auditter_2.1.0_linux_amd64.rpm
sudo rpm -i auditter_2.1.0_linux_amd64.rpm` 
  },
  { 
    name: "Alpine Linux", 
    command: `curl -LO https://github.com/kluth/npm-security-auditter/releases/latest/download/auditter_2.1.0_linux_amd64.apk
sudo apk add --allow-untrusted auditter_2.1.0_linux_amd64.apk` 
  }
];

export function Installation() {
  const [activeOS, setActiveOS] = React.useState(0);

  return (
    <section id="installation" className="py-24 bg-neutral-900/30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-5xl font-bold mb-4">Install Auditter</h2>
          <p className="text-neutral-400 text-lg max-w-2xl mx-auto">
            Available for all major operating systems. Pre-built binaries are ready for your platform.
          </p>
        </div>

        <div className="max-w-4xl mx-auto p-8 rounded-3xl bg-neutral-900 border border-neutral-800 shadow-2xl overflow-hidden relative group">
          <div className="absolute top-0 right-0 p-4 opacity-50 group-hover:opacity-100 transition-opacity">
             <Terminal className="w-12 h-12 text-blue-500/20" />
          </div>

          <div className="flex flex-wrap gap-4 mb-8">
            {osOptions.map((os, i) => (
              <button
                key={i}
                onClick={() => setActiveOS(i)}
                className={`px-4 py-2 rounded-xl text-sm font-bold transition-all ${
                  activeOS === i 
                  ? "bg-blue-600 text-white shadow-lg shadow-blue-600/20" 
                  : "bg-neutral-800 text-neutral-400 hover:bg-neutral-700"
                }`}
              >
                {os.name}
              </button>
            ))}
          </div>

          <div className="p-6 rounded-2xl bg-neutral-950 border border-neutral-800 font-mono text-sm leading-relaxed overflow-x-auto">
            <pre className="text-blue-400 whitespace-pre-wrap">
              {osOptions[activeOS].command}
            </pre>
          </div>

          <div className="mt-8 flex flex-col md:flex-row gap-6 items-center justify-between pt-8 border-t border-neutral-800">
             <div className="flex items-center gap-4">
                <a 
                  href="https://github.com/kluth/npm-security-auditter/releases"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-4 py-2 rounded-xl bg-neutral-800 hover:bg-neutral-700 text-sm font-bold transition-all"
                >
                  <Download className="w-4 h-4" />
                  All Releases
                </a>
                <a 
                  href="https://github.com/kluth/npm-security-auditter"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-4 py-2 rounded-xl bg-neutral-800 hover:bg-neutral-700 text-sm font-bold transition-all"
                >
                  <Github className="w-4 h-4" />
                  Source Code
                </a>
             </div>
             <p className="text-xs text-neutral-500 uppercase tracking-widest font-bold">
               Requires Go 1.23+ for source builds
             </p>
          </div>
        </div>
      </div>
    </section>
  );
}
