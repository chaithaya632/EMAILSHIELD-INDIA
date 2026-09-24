// web/app/diagnostics/page.tsx
"use client";

import { useEffect, useState, useCallback } from "react";
import { fetchDiagnostics } from "@/lib/api";
import type { DiagnosticsData } from "@/lib/types/soc";
import { Card, CardHeader } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/Badge";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { ErrorState } from "@/components/ui/States";
import { Header } from "@/components/Header";
import { formatRelative } from "@/lib/constants";
import {
  ChevronDown,
  Server,
  Clock,
  Hash,
  Heart,
  Database,
  Shield,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  RefreshCw,
} from "lucide-react";

export default function DiagnosticsPage() {
  const [data, setData] = useState<DiagnosticsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    setError(false);
    fetchDiagnostics()
      .then(setData)
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const healthIcons = {
    healthy: { icon: CheckCircle2, color: "text-status-connected" },
    degraded: { icon: AlertTriangle, color: "text-status-processing" },
    down: { icon: XCircle, color: "text-status-error" },
  };

  const authIcons = {
    authenticated: { icon: CheckCircle2, color: "text-status-connected" },
    unauthenticated: { icon: XCircle, color: "text-status-error" },
    expired: { icon: AlertTriangle, color: "text-status-processing" },
  };

  const items = data
    ? [
        {
          label: "Live Mail Worker Status",
          value: <StatusBadge status={data.worker_status} />,
          icon: Server,
        },
        {
          label: "Last IMAP Checkpoint Poll",
          value: (
            <span className="text-xs font-mono text-slate-300">
              {data.last_poll ? formatRelative(data.last_poll) : "—"}
            </span>
          ),
          icon: Clock,
        },
        {
          label: "Authoritative Last UID",
          value: <span className="text-xs font-mono text-slate-300">UID #{data.last_uid}</span>,
          icon: Hash,
        },
        {
          label: "Next.js API Gateway Health",
          value: (
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="h-4 w-4 text-status-connected" />
              <span className="text-xs font-mono text-status-connected uppercase">{data.api_health}</span>
            </div>
          ),
          icon: Heart,
        },
        {
          label: "PostgreSQL & RLS Auth Engine",
          value: (
            <div className="flex items-center gap-1.5">
              <Database className="h-4 w-4 text-status-connected" />
              <span className="text-xs font-mono text-status-connected uppercase">{data.supabase_health}</span>
            </div>
          ),
          icon: Database,
        },
        {
          label: "Caller Session Auth Status",
          value: (
            <div className="flex items-center gap-1.5">
              <Shield className="h-4 w-4 text-status-connected" />
              <span className="text-xs font-mono text-status-connected uppercase">{data.auth_status}</span>
            </div>
          ),
          icon: Shield,
        },
      ]
    : [];

  return (
    <div className="flex flex-col flex-1 min-w-0">
      <Header
        title="Diagnostics"
        description="Operational health matrix and system diagnostics"
        actions={
          <button
            onClick={load}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-soc-surface-2 text-slate-300 hover:text-white hover:bg-soc-surface-3 transition-colors border border-soc-border"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            <span>Refresh</span>
          </button>
        }
      />

      <div className="p-4 lg:p-6 space-y-6 flex-1 animate-fade-in">
        {loading ? (
          <SkeletonCard lines={6} />
        ) : error || !data ? (
          <ErrorState type="unavailable" onRetry={load} />
        ) : (
          <>
            <Card surface={2}>
              <button
                onClick={() => setExpanded(!expanded)}
                className="flex items-center justify-between w-full"
                aria-expanded={expanded}
              >
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-lg bg-soc-surface-3">
                    <Server className="h-5 w-5 text-accent" />
                  </div>
                  <div className="text-left">
                    <p className="text-sm font-semibold text-slate-100">System Diagnostics Matrix</p>
                    <p className="text-xs text-slate-500">Autonomous service health and connectivity</p>
                  </div>
                </div>
                <ChevronDown
                  className={`h-5 w-5 text-slate-500 transition-transform ${expanded ? "rotate-180" : ""}`}
                />
              </button>
            </Card>

            {expanded && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 animate-slide-up">
                {items.map((item) => {
                  const Icon = item.icon;
                  return (
                    <Card key={item.label} surface={2}>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <Icon className="h-4 w-4 text-slate-500" />
                          <span className="text-xs text-slate-300">{item.label}</span>
                        </div>
                        {item.value}
                      </div>
                    </Card>
                  );
                })}
              </div>
            )}

            <Card surface={2}>
              <div className="flex items-center gap-2 text-xs text-slate-500 font-mono">
                <Shield className="h-3.5 w-3.5 text-accent" />
                <span>
                  Authoritative diagnostic telemetry derived under active caller credentials without administrative elevation.
                </span>
              </div>
            </Card>
          </>
        )}
      </div>
    </div>
  );
}
