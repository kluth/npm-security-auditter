import { Shield, Github } from 'lucide-react';

export function Navbar() {
  return (
    <nav className="fixed top-0 w-full z-50 bg-neutral-950/80 backdrop-blur-md border-b border-neutral-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center gap-2">
            <Shield className="w-8 h-8 text-blue-500" />
            <span className="text-xl font-bold tracking-tight">auditter</span>
          </div>
          <div className="hidden md:block">
            <div className="ml-10 flex items-baseline space-x-8">
              <a href="#features" className="text-neutral-300 hover:text-white transition-colors">Features</a>
              <a href="#analyzers" className="text-neutral-300 hover:text-white transition-colors">Analyzers</a>
              <a href="#usage" className="text-neutral-300 hover:text-white transition-colors">Usage</a>
              <a href="#cicd" className="text-neutral-300 hover:text-white transition-colors">CI/CD</a>
              <a href="#installation" className="text-neutral-300 hover:text-white transition-colors">Installation</a>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <a 
              href="https://github.com/kluth/npm-security-auditter" 
              target="_blank" 
              rel="noopener noreferrer"
              className="p-2 text-neutral-400 hover:text-white transition-colors"
            >
              <Github className="w-6 h-6" />
            </a>
            <a 
              href="#installation" 
              className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-medium transition-all"
            >
              Get Started
            </a>
          </div>
        </div>
      </div>
    </nav>
  );
}
