import { Shield, Github, Heart } from 'lucide-react';

export function Footer() {
  return (
    <footer className="py-12 border-t border-neutral-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row items-center justify-between gap-8">
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-blue-500" />
            <span className="text-lg font-bold tracking-tight">auditter</span>
          </div>
          
          <div className="flex items-center gap-8 text-sm text-neutral-400">
            <a href="https://github.com/kluth/npm-security-auditter/blob/main/LICENSE" className="hover:text-white transition-colors">License</a>
            <a href="https://github.com/kluth/npm-security-auditter/blob/main/CONTRIBUTING.md" className="hover:text-white transition-colors">Contributing</a>
            <a href="https://github.com/kluth/npm-security-auditter/blob/main/SECURITY.md" className="hover:text-white transition-colors">Security</a>
          </div>

          <div className="flex items-center gap-4">
            <a 
              href="https://github.com/kluth/npm-security-auditter" 
              target="_blank" 
              rel="noopener noreferrer"
              className="p-2 text-neutral-400 hover:text-white transition-colors"
            >
              <Github className="w-5 h-5" />
            </a>
          </div>
        </div>
        
        <div className="mt-12 text-center text-sm text-neutral-500 flex items-center justify-center gap-1">
          Made with <Heart className="w-4 h-4 text-red-500 fill-red-500" /> for a safer npm ecosystem
        </div>
      </div>
    </footer>
  );
}
