// web/components/Sidebar.tsx
"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  LayoutDashboard,
  Search,
  Radio,
  UserSearch,
  Globe,
  Network,
  FileText,
  Smartphone,
  Settings,
  Stethoscope,
  ShieldCheck,
  LogOut,
  ChevronLeft,
  ChevronRight,
  CircleDot,
} from "lucide-react";

export interface NavItem {
  key: string;
  href: string;
  label: string;
  icon: typeof LayoutDashboard;
}

export const NAV_ITEMS: NavItem[] = [
  { key: "dashboard", href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { key: "analyze", href: "/analyze", label: "Analyze Email", icon: Search },
  { key: "live-mail", href: "/live-mail", label: "Live Mail Analysis", icon: Radio },
  { key: "investigations", href: "/investigations", label: "Investigations", icon: UserSearch },
  { key: "intel", href: "/intel", label: "IOC / URL Intelligence", icon: Globe },
  { key: "attack-graph", href: "/attack-graph", label: "Attack Graph", icon: Network },
  { key: "reports", href: "/reports", label: "Evidence & Reports", icon: FileText },
  { key: "alerts", href: "/alerts", label: "Mobile Alerts", icon: Smartphone },
  { key: "settings", href: "/settings", label: "Settings", icon: Settings },
  { key: "diagnostics", href: "/diagnostics", label: "Diagnostics", icon: Stethoscope },
];

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const [collapsed, setCollapsed] = useState(false);

  async function handleLogout() {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
      router.push("/login");
      router.refresh();
    } catch {
      router.push("/login");
    }
  }

  // Hide sidebar entirely on login route
  if (pathname === "/login") return null;

  return (
    <aside
      className={`border-r border-soc-border bg-soc-bg flex flex-col h-screen sticky top-0 transition-all duration-200 z-30 shrink-0 ${
        collapsed ? "w-16" : "w-64"
      }`}
    >
      {/* Brand Header */}
      <div className="h-14 flex items-center px-4 border-b border-soc-border shrink-0">
        <div className="flex items-center gap-2.5 min-w-0 flex-1">
          <div className="p-1.5 rounded-lg bg-accent/10 border border-accent/20 shrink-0">
            <ShieldCheck className="h-5 w-5 text-accent" />
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <span className="font-bold text-sm tracking-tight text-slate-100 font-mono block leading-tight">
                EMAILSHIELD <span className="text-accent font-mono">INDIA</span>
              </span>
              <span className="ops-eyebrow block">SOC CONSOLE</span>
            </div>
          )}
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-2 py-3 space-y-1 overflow-y-auto scrollbar-thin">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href || (item.href !== "/dashboard" && pathname.startsWith(item.href));

          return (
            <Link
              key={item.href}
              href={item.href}
              title={collapsed ? item.label : undefined}
              className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                isActive
                  ? "bg-accent/15 text-accent border border-accent/30 font-semibold"
                  : "text-slate-400 hover:text-slate-100 hover:bg-soc-surface-2"
              } ${collapsed ? "justify-center px-2" : ""}`}
            >
              <Icon className={`h-4 w-4 shrink-0 ${isActive ? "text-accent" : "text-slate-500"}`} />
              {!collapsed && <span className="truncate">{item.label}</span>}
            </Link>
          );
        })}
      </nav>

      {/* Session State Footer */}
      <div className="p-3 border-t border-soc-border shrink-0 space-y-2">
        {!collapsed && (
          <div className="px-2 py-1 flex items-center gap-2 text-[0.65rem] text-slate-500 font-mono">
            <CircleDot className="h-3 w-3 text-status-connected shrink-0" />
            <span className="truncate">RLS SESSION ACTIVE</span>
          </div>
        )}

        <button
          onClick={handleLogout}
          title={collapsed ? "Logout" : undefined}
          className={`flex items-center gap-3 w-full px-3 py-2 text-xs font-medium text-severity-critical hover:bg-severity-critical-bg/30 rounded-md transition-colors ${
            collapsed ? "justify-center px-2" : ""
          }`}
        >
          <LogOut className="h-4 w-4 shrink-0" />
          {!collapsed && <span>Logout</span>}
        </button>

        {/* Collapse / Expand Toggle Button */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="hidden md:flex items-center justify-center w-full py-1.5 border-t border-soc-border text-slate-500 hover:text-slate-300 hover:bg-soc-surface-2 transition-colors rounded text-xs"
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </button>
      </div>
    </aside>
  );
}
