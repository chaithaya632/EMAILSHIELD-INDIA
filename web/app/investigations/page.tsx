// web/app/investigations/page.tsx
"use client";

import { useEffect, useState, useCallback } from "react";
import { fetchInvestigations, fetchInvestigation } from "@/lib/api";
import type { CaseSummary, CaseDetail, Severity } from "@/lib/types/soc";
import { Card, CardHeader } from "@/components/ui/Card";
import { SeverityBadge } from "@/components/ui/Badge";
import { SearchBar, FilterBar, FilterChip } from "@/components/ui/SearchBar";
import { SkeletonList, SkeletonCard } from "@/components/ui/Skeleton";
import { EmptyState, ErrorState } from "@/components/ui/States";
import { EvidenceBlock } from "@/components/ui/EvidenceBlock";
import { Timeline } from "@/components/ui/Timeline";
import { Tabs } from "@/components/ui/Accordion";
import { Header } from "@/components/Header";
import { formatDate, formatRelative } from "@/lib/constants";
import { Briefcase, ChevronRight, RefreshCw } from "lucide-react";

export default function InvestigationsPage() {
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [activeSev, setActiveSev] = useState<Severity | null>(null);
  const [activeTab, setActiveTab] = useState("evidence");

  const load = useCallback(() => {
    setLoading(true);
    setError(false);
    fetchInvestigations()
      .then((c) => {
        setCases(c);
        if (c.length > 0 && !selectedId) setSelectedId(c[0].id);
      })
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, [selectedId]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!selectedId) {
      setDetail(null);
      return;
    }
    setDetailLoading(true);
    fetchInvestigation(selectedId)
      .then(setDetail)
      .catch(() => setDetail(null))
      .finally(() => setDetailLoading(false));
  }, [selectedId]);

  const filtered = cases.filter((c) => {
    if (activeSev && c.severity !== activeSev) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return c.subject.toLowerCase().includes(q) || c.id.toLowerCase().includes(q);
    }
    return true;
  });

  const detailTabs = [
    { id: "evidence", label: "Evidence", count: detail?.evidence.length },
    { id: "timeline", label: "Timeline", count: detail?.timeline.length },
    { id: "indicators", label: "Indicators", count: detail?.indicators.length },
    { id: "related", label: "Related Emails", count: detail?.related_emails.length },
    { id: "relationships", label: "Relationships", count: detail?.attack_relationships.length },
    { id: "reports", label: "Reports", count: detail?.reports.length },
  ];

  return (
    <div className="flex flex-col flex-1 min-w-0">
      <Header
        title="Investigations"
        description="Case management and forensic investigation workspace"
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

      <div className="p-4 lg:p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1 animate-fade-in">
        {/* Cases master list */}
        <div className="space-y-4">
          <Card surface={2} noPadding>
            <div className="p-3 border-b border-soc-border space-y-2">
              <SearchBar
                value={search}
                onChange={setSearch}
                onClear={() => setSearch("")}
                placeholder="Search cases..."
              />
              <FilterBar>
                <FilterChip
                  label="All"
                  active={activeSev === null}
                  onClick={() => setActiveSev(null)}
                />
                {(["critical", "high", "suspicious", "clean"] as Severity[]).map((s) => (
                  <FilterChip
                    key={s}
                    label={s}
                    active={activeSev === s}
                    onClick={() => setActiveSev(activeSev === s ? null : s)}
                  />
                ))}
              </FilterBar>
            </div>

            <div className="max-h-[600px] overflow-y-auto scrollbar-thin">
              {loading ? (
                <div className="p-3">
                  <SkeletonList items={6} />
                </div>
              ) : error ? (
                <ErrorState type="unavailable" onRetry={load} />
              ) : filtered.length === 0 ? (
                <EmptyState
                  icon={<Briefcase className="h-8 w-8" />}
                  title="No cases found."
                  message={search || activeSev ? "Try adjusting your filters." : "No investigations recorded."}
                />
              ) : (
                <div className="divide-y divide-soc-border">
                  {filtered.map((c) => (
                    <button
                      key={c.id}
                      onClick={() => setSelectedId(c.id)}
                      className={`flex items-center gap-3 w-full p-3 text-left hover:bg-soc-surface-2 transition-colors ${
                        selectedId === c.id ? "bg-soc-surface-2 border-l-2 border-l-accent" : ""
                      }`}
                    >
                      <SeverityBadge severity={c.severity} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-slate-200 truncate">{c.subject}</p>
                        <p className="text-xs text-slate-500 font-mono">
                          {c.id} · {formatRelative(c.created)}
                        </p>
                      </div>
                      <span className="text-xs text-slate-500 capitalize hidden sm:block">
                        {c.status.replace("_", " ")}
                      </span>
                      <ChevronRight className="h-4 w-4 text-slate-600 shrink-0" />
                    </button>
                  ))}
                </div>
              )}
            </div>
          </Card>
        </div>

        {/* Case detail pane */}
        <div className="lg:col-span-2">
          {!selectedId ? (
            <Card surface={2}>
              <EmptyState
                icon={<Briefcase className="h-8 w-8" />}
                title="Select a case"
                message="Choose an incident case from the list to view its forensic evidence."
              />
            </Card>
          ) : detailLoading ? (
            <SkeletonCard lines={10} />
          ) : !detail ? (
            <Card surface={2}>
              <ErrorState type="unavailable" />
            </Card>
          ) : (
            <Card surface={2} noPadding>
              {/* Case header */}
              <div className="p-4 border-b border-soc-border">
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-mono text-slate-500">{detail.id}</span>
                      <SeverityBadge severity={detail.severity} />
                      <span className="text-xs text-slate-500 capitalize px-2 py-0.5 rounded bg-soc-surface-3">
                        {detail.status.replace("_", " ")}
                      </span>
                    </div>
                    <h2 className="text-lg font-semibold text-slate-100">{detail.subject}</h2>
                    <p className="text-xs text-slate-500 mt-1">
                      Created {formatDate(detail.created)}
                      {detail.assigned_to && ` · Assigned to ${detail.assigned_to}`}
                    </p>
                  </div>
                </div>
              </div>

              {/* Case overview */}
              <div className="px-4 py-3 bg-soc-surface border-b border-soc-border text-xs text-slate-400 font-mono">
                {detail.overview}
              </div>

              {/* Tabs */}
              <div className="px-4 pt-2">
                <Tabs tabs={detailTabs} activeId={activeTab} onChange={setActiveTab} />
              </div>

              {/* Tab content */}
              <div className="p-4">
                {activeTab === "evidence" && <EvidenceBlock items={detail.evidence} />}
                {activeTab === "timeline" && <Timeline events={detail.timeline} />}
                {activeTab === "indicators" &&
                  (detail.indicators.length > 0 ? (
                    <div className="space-y-2">
                      {detail.indicators.map((ind, i) => (
                        <div
                          key={i}
                          className="flex items-center gap-3 p-3 bg-soc-surface border border-soc-border rounded-md"
                        >
                          <span className="text-xs font-mono text-slate-500 uppercase shrink-0 w-16">
                            {ind.type}
                          </span>
                          <span className="text-sm text-slate-200 font-mono flex-1 truncate">{ind.value}</span>
                          {ind.risk && <SeverityBadge severity={ind.risk} />}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <EmptyState title="No indicators extracted." />
                  ))}
                {activeTab === "related" &&
                  (detail.related_emails.length > 0 ? (
                    <div className="space-y-2">
                      {detail.related_emails.map((e) => (
                        <div
                          key={e.uid}
                          className="flex items-center gap-3 p-3 bg-soc-surface border border-soc-border rounded-md"
                        >
                          <SeverityBadge severity={e.risk_status} />
                          <div className="flex-1 min-w-0">
                            <p className="text-sm text-slate-200 truncate">{e.subject}</p>
                            <p className="text-xs text-slate-500 font-mono">
                              {e.sender} · {formatDate(e.date)}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <EmptyState title="No related emails." />
                  ))}
                {activeTab === "relationships" &&
                  (detail.attack_relationships.length > 0 ? (
                    <div className="space-y-2">
                      {detail.attack_relationships.map((rel, i) => (
                        <div
                          key={i}
                          className="flex items-center gap-3 p-3 bg-soc-surface border border-soc-border rounded-md"
                        >
                          <span className="text-xs text-slate-500 uppercase shrink-0 w-20 font-mono">
                            {rel.type}
                          </span>
                          <span className="text-sm text-slate-200 font-mono flex-1 truncate">{rel.node}</span>
                          <SeverityBadge severity={rel.risk} />
                        </div>
                      ))}
                    </div>
                  ) : (
                    <EmptyState title="No attack relationships." />
                  ))}
                {activeTab === "reports" &&
                  (detail.reports.length > 0 ? (
                    <div className="space-y-2">
                      {detail.reports.map((r) => (
                        <div
                          key={r.id}
                          className="flex items-center gap-3 p-3 bg-soc-surface border border-soc-border rounded-md"
                        >
                          <span className="text-xs font-mono text-accent shrink-0 font-bold">{r.type}</span>
                          <span className="text-sm text-slate-300 flex-1 font-mono">{r.id}</span>
                          <span className="text-xs text-slate-500">{formatDate(r.created)}</span>
                          <span className="text-xs text-status-connected font-medium uppercase">{r.status}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <EmptyState title="No reports available." />
                  ))}
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
