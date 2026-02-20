interface TerminalWindowProps {
  title: string;
  children: React.ReactNode;
  className?: string;
}

export function TerminalWindow({ title, children, className = '' }: TerminalWindowProps) {
  return (
    <div className={`bg-[#1e1e1e] rounded-lg overflow-hidden border border-neutral-800 shadow-2xl font-mono text-sm ${className}`}>
      <div className="flex items-center px-4 py-2 bg-[#2d2d2d] border-b border-neutral-700">
        <div className="flex space-x-2 mr-4">
          <div className="w-3 h-3 rounded-full bg-red-500" />
          <div className="w-3 h-3 rounded-full bg-yellow-500" />
          <div className="w-3 h-3 rounded-full bg-green-500" />
        </div>
        <div className="text-neutral-400 text-xs flex-1 text-center font-semibold">{title}</div>
      </div>
      <div className="p-4 text-neutral-300 overflow-x-auto whitespace-pre font-mono">
        {children}
      </div>
    </div>
  );
}
