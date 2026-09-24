// web/components/ui/Accordion.tsx
"use client";

import { type ReactNode, useState } from 'react';
import { ChevronDown } from 'lucide-react';

interface AccordionItem {
  id: string;
  title: string;
  badge?: ReactNode;
  children: ReactNode;
  defaultOpen?: boolean;
}

export function Accordion({ items }: { items: AccordionItem[] }) {
  const [openIds, setOpenIds] = useState<Set<string>>(
    () => new Set(items.filter((i) => i.defaultOpen).map((i) => i.id))
  );

  const toggle = (id: string) => {
    setOpenIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div className="divide-y divide-soc-border">
      {items.map((item) => {
        const isOpen = openIds.has(item.id);
        return (
          <div key={item.id}>
            <button
              onClick={() => toggle(item.id)}
              className="flex items-center justify-between w-full py-3 text-left hover:bg-soc-surface-2/50 px-3 -mx-3 rounded transition-colors"
              aria-expanded={isOpen}
            >
              <span className="flex items-center gap-3">
                <span className="text-sm font-medium text-slate-200">{item.title}</span>
                {item.badge}
              </span>
              <ChevronDown
                className={`h-4 w-4 text-slate-500 transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`}
              />
            </button>
            {isOpen && (
              <div className="pb-4 pt-1 px-3 animate-fade-in">{item.children}</div>
            )}
          </div>
        );
      })}
    </div>
  );
}

interface TabsProps {
  tabs: { id: string; label: string; count?: number }[];
  activeId: string;
  onChange: (id: string) => void;
}

export function Tabs({ tabs, activeId, onChange }: TabsProps) {
  return (
    <div className="flex items-center gap-1 border-b border-soc-border overflow-x-auto scrollbar-thin">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          onClick={() => onChange(tab.id)}
          className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
            activeId === tab.id
              ? 'border-accent text-accent'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-soc-border-light'
          }`}
        >
          {tab.label}
          {tab.count !== undefined && (
            <span className="ml-2 text-xs text-slate-500">{tab.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}
