// web/components/Header.tsx
"use client";

import { type ReactNode } from "react";
import { CircleDot } from "lucide-react";

interface HeaderProps {
  title: string;
  description: string;
  actions?: ReactNode;
}

export function Header({ title, description, actions }: HeaderProps) {
  return (
    <header className="sticky top-0 z-20 bg-soc-bg/95 backdrop-blur border-b border-soc-border h-14 flex items-center px-4 lg:px-6 gap-4 shrink-0">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="hidden sm:block ops-eyebrow">SOC /</span>
          <h1 className="text-base lg:text-lg font-semibold text-slate-100 truncate">{title}</h1>
        </div>
        <p className="text-xs text-slate-500 truncate hidden sm:block">{description}</p>
      </div>

      <div className="hidden md:flex items-center gap-2 text-[0.65rem] text-slate-500 font-mono px-2 py-1 rounded bg-soc-surface border border-soc-border">
        <CircleDot className="h-2.5 w-2.5 text-status-connected animate-pulse" />
        <span>AUTHENTICATED</span>
      </div>

      {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
    </header>
  );
}
