// web/app/dashboard/page.tsx
"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { fetchDashboard } from "@/lib/api";
import type { DashboardData } from "@/lib/types/soc";
import { Card, CardHeader } from "@/components/ui/Card";
import { SeverityBadge } from "@/components/ui/Badge";
import { SkeletonKPI, SkeletonCard } from "@/components/ui/Skeleton";
import { EmptyState, ErrorState } from "@/components/ui/States";
import { Header } from "@/components/Header";
import { formatDate, formatRelative } from "@/lib/constants";
import {
  Briefcase,
  AlertTriangle,
  Eye,
  ShieldCheck,
  TrendingUp,
  Activity,
  ArrowRight,
  RefreshCw,
} from "lucide-react";

export default function DashboardPage() {
  const router = useRouter();
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    setError(false);
    fetchDashboard()
      .then((d) => setData(d))
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const onNavigate = (page: string) => {
    router.push(`/${page}`);
  };

  return (
    <div className="flex flex-col flex-1 min-w-0">
      <Header
        title="Dashboard"
        description="Security operations overview and threat activity"
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
          <div className="space-y-6 animate-pulse">
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {Array.from({ length: 4 }).map((_, i) => (
                <SkeletonKPI key={i} />
              ))}
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <SkeletonCard lines={6} />
              <SkeletonCard lines={6} />
            </div>
          </div>
        ) : error ? (
          <ErrorState type="unavailable" onRetry={load} />
        ) : !data ? (
          <EmptyState
            title="No investigation data available."
            message="Data will appear here once investigations are conducted."
          />
        ) : (
          <>
            {/* KPI Row */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                { label: "Total Emails Analyzed", value: data.total_cases, icon: Briefcase, color: "text-accent" },
                { label: "High / Critical", value: data.high_critical, icon: AlertTriangle, color: "text-severity-critical" },
                { label: "Suspicious", value: data.suspicious, icon: Eye, color: "text-severity-suspicious" },
                { label: "Clean", value: data.clean, icon: ShieldCheck, color: "text-severity-clean" },
              ].map((kpi) => {
                const Icon = kpi.icon;
                return (
                  <Card key={kpi.label} surface={2}>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-xs text-slate-400 font-medium">{kpi.label}</p>
                        <p className="text-2xl lg:text-3xl font-bold text-slate-100 mt-1">
                          {kpi.value.toLocaleString("en-IN")}
                        </p>
                      </div>
                      <div className={`p-2.5 rounded-lg bg-soc-surface-3 ${kpi.color}`}>
                        <Icon className="h-5 w-5" />
                      </div>
                    </div>
                  </Card>
                );
              })}
            </div>

            {/* Threat Distribution + Timeline */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <Card surface={2}>
                <CardHeader title="Threat Distribution Ratio" subtitle="By severity classification" />
                <div className="space-y-3">
                  {Object.entries(data.threat_distribution).map(([sev, count]) => {
                    const distTotal = Object.values(data.threat_distribution).reduce((a, b) => a + b, 0) || 1;
                    const pct = (count / distTotal) * 100;
                    const colors: Record<string, string> = {
                      critical: "bg-severity-critical",
                      high: "bg-severity-high",
                      suspicious: "bg-severity-suspicious",
                      clean: "bg-severity-clean",
                    };
                    return (
                      <div key={sev}>
                        <div className="flex items-center justify-between text-xs mb-1">
                          <span className="text-slate-300 capitalize font-medium">{sev}</span>
                          <span className="text-slate-500 font-mono">{count}</span>
                        </div>
                        <div className="h-2 bg-soc-surface-3 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all duration-500 ${colors[sev] ?? "bg-slate-600"}`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                  {Object.keys(data.threat_distribution).length === 0 && (
                    <p className="text-xs text-slate-500 text-center py-4">No threat data available.</p>
                  )}
                </div>
              </Card>

              <Card surface={2}>
                <CardHeader title="Threat Activity Timeline" subtitle="Recent threat detections over time" />
                {data.threat_timeline.length > 0 ? (
                  <div className="flex items-end gap-1.5 h-40">
                    {data.threat_timeline.slice(-30).map((pt, i) => {
                      const maxTimeline = Math.max(...data.threat_timeline.map((t) => t.count), 1);
                      return (
                        <div key={i} className="flex-1 flex flex-col items-center gap-1 group">
                          <div
                            className="w-full bg-accent/60 hover:bg-accent rounded-t transition-all duration-200 min-h-[4px]"
                            style={{ height: `${Math.max((pt.count / maxTimeline) * 100, 10)}%` }}
                            title={`${pt.date}: ${pt.count} threats`}
                          />
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="flex items-center justify-center h-40 text-xs text-slate-500">
                    <TrendingUp className="h-5 w-5 mr-2 text-slate-600" />
                    No timeline data available.
                  </div>
                )}
              </Card>
            </div>

            {/* Investigation Queue + Recent Cases */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <Card surface={2}>
                <CardHeader
                  title="Incident Triage Queue"
                  subtitle="Cases awaiting action"
                  action={
                    <button
                      onClick={() => onNavigate("investigations")}
                      className="text-xs text-accent hover:text-accent-hover flex items-center gap-1"
                    >
                      View all <ArrowRight className="h-3 w-3" />
                    </button>
                  }
                />
                {data.investigation_queue.length > 0 ? (
                  <div className="space-y-2">
                    {data.investigation_queue.slice(0, 5).map((item) => (
                      <div
                        key={item.id}
                        className="flex items-center gap-3 p-2.5 rounded-md bg-soc-surface border border-soc-border hover:border-soc-border-light transition-colors cursor-pointer"
                        onClick={() => onNavigate("investigations")}
                      >
                        <SeverityBadge severity={item.severity} />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-slate-200 truncate">{item.subject}</p>
                          <p className="text-xs text-slate-500">{item.id} · {formatRelative(item.created)}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyState icon={<Activity className="h-8 w-8" />} title="No cases in queue." />
                )}
              </Card>

              <Card surface={2}>
                <CardHeader
                  title="Recent Cases"
                  subtitle="Latest investigation activity"
                  action={
                    <button
                      onClick={() => onNavigate("investigations")}
                      className="text-xs text-accent hover:text-accent-hover flex items-center gap-1"
                    >
                      View all <ArrowRight className="h-3 w-3" />
                    </button>
                  }
                />
                {data.recent_cases.length > 0 ? (
                  <div className="space-y-2">
                    {data.recent_cases.slice(0, 5).map((c) => (
                      <div
                        key={c.id}
                        className="flex items-center gap-3 p-2.5 rounded-md bg-soc-surface border border-soc-border hover:border-soc-border-light transition-colors cursor-pointer"
                        onClick={() => onNavigate("investigations")}
                      >
                        <SeverityBadge severity={c.severity} />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-slate-200 truncate">{c.subject}</p>
                          <p className="text-xs text-slate-500">{c.id} · {formatDate(c.created)}</p>
                        </div>
                        <span className="text-xs text-slate-500 capitalize">{c.status.replace("_", " ")}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyState title="No recent cases." />
                )}
              </Card>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
