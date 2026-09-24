// web/components/ui/SearchBar.tsx
import { type ReactNode } from 'react';
import { Search, X } from 'lucide-react';

interface SearchBarProps {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  onClear?: () => void;
}

export function SearchBar({ value, onChange, placeholder = 'Search...', onClear }: SearchBarProps) {
  return (
    <div className="relative flex-1 min-w-0">
      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500 pointer-events-none" />
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full bg-soc-surface-2 border border-soc-border-light rounded-md pl-9 pr-9 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-accent transition-colors"
      />
      {value && onClear && (
        <button
          onClick={onClear}
          className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
          aria-label="Clear search"
        >
          <X className="h-4 w-4" />
        </button>
      )}
    </div>
  );
}

interface FilterBarProps {
  children: ReactNode;
}

export function FilterBar({ children }: FilterBarProps) {
  return (
    <div className="flex items-center gap-2 flex-wrap">
      {children}
    </div>
  );
}

interface FilterChipProps {
  label: string;
  active: boolean;
  onClick: () => void;
}

export function FilterChip({ label, active, onClick }: FilterChipProps) {
  return (
    <button
      onClick={onClick}
      className={`text-xs font-medium px-3 py-1.5 rounded-md border transition-colors ${
        active
          ? 'bg-accent/15 text-accent border-accent/40'
          : 'bg-soc-surface-2 text-slate-400 border-soc-border-light hover:text-slate-200 hover:border-soc-border-hover'
      }`}
    >
      {label}
    </button>
  );
}
