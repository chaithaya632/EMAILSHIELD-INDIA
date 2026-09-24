// web/app/attack-graph/page.tsx
"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import { fetchAttackGraph } from "@/lib/api";
import type { AttackGraphData, GraphNode, Severity } from "@/lib/types/soc";
import { Card } from "@/components/ui/Card";
import { SeverityBadge } from "@/components/ui/Badge";
import { FilterBar, FilterChip } from "@/components/ui/SearchBar";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { EmptyState, ErrorState } from "@/components/ui/States";
import { Header } from "@/components/Header";
import { SEVERITY_DOT } from "@/lib/constants";
import {
  Network,
  ZoomIn,
  ZoomOut,
  Maximize,
  RotateCcw,
  RefreshCw,
} from "lucide-react";

const nodeColors: Record<string, string> = {
  email: "#3B82F6",
  ip: "#8B5CF6",
  domain: "#EC4899",
  url: "#F59E0B",
  case: "#2BB7A9",
};

export default function AttackGraphPage() {
  const [data, setData] = useState<AttackGraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [sevFilter, setSevFilter] = useState<Set<Severity>>(new Set());
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const dragStart = useRef({ x: 0, y: 0 });

  const load = useCallback(() => {
    setLoading(true);
    setError(false);
    fetchAttackGraph()
      .then(setData)
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const toggleSev = (s: Severity) => {
    setSevFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  const reset = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    setDragging(true);
    dragStart.current = { x: e.clientX - pan.x, y: e.clientY - pan.y };
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!dragging) return;
    setPan({ x: e.clientX - dragStart.current.x, y: e.clientY - dragStart.current.y });
  };

  const handleMouseUp = () => setDragging(false);

  const filteredNodes = (data?.nodes ?? []).filter((n) => {
    if (sevFilter.size === 0) return true;
    return sevFilter.has(n.risk);
  });

  const nodeIds = new Set(filteredNodes.map((n) => n.id));
  const filteredEdges = (data?.edges ?? []).filter(
    (e) => nodeIds.has(e.source) && nodeIds.has(e.target)
  );

  // Position nodes in a circular formation if not explicitly positioned
  const count = filteredNodes.length;
  const radius = Math.min(220, Math.max(120, count * 25));
  const centerX = 320;
  const centerY = 240;

  const layoutedNodes = filteredNodes.map((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(count, 1);
    return {
      ...n,
      x: n.x ?? centerX + radius * Math.cos(angle),
      y: n.y ?? centerY + radius * Math.sin(angle),
    };
  });

  return (
    <div className="flex flex-col flex-1 min-w-0">
      <Header
        title="Attack Graph"
        description="Visualize relationships between emails, indicators, and incident cases"
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

      <div className="p-4 lg:p-6 space-y-4 flex-1 animate-fade-in">
        {/* Controls */}
        <Card surface={2}>
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-medium">Risk Filter:</span>
              <FilterBar>
                {(["critical", "high", "suspicious", "clean"] as Severity[]).map((s) => (
                  <FilterChip
                    key={s}
                    label={s}
                    active={sevFilter.size === 0 || sevFilter.has(s)}
                    onClick={() => toggleSev(s)}
                  />
                ))}
              </FilterBar>
            </div>
          </div>
        </Card>

        {loading ? (
          <SkeletonCard lines={10} />
        ) : error ? (
          <ErrorState type="connection" onRetry={load} />
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
            {/* Graph Canvas */}
            <div className="lg:col-span-3">
              <Card surface={2} noPadding>
                <div className="flex items-center justify-between p-3 border-b border-soc-border">
                  <p className="text-sm font-semibold text-slate-200">Interactive Forensic Topology</p>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => setZoom((z) => Math.max(0.3, z - 0.1))}
                      className="p-1.5 rounded hover:bg-soc-surface-3 text-slate-400"
                      aria-label="Zoom out"
                    >
                      <ZoomOut className="h-4 w-4" />
                    </button>
                    <span className="text-xs text-slate-500 font-mono w-12 text-center">
                      {Math.round(zoom * 100)}%
                    </span>
                    <button
                      onClick={() => setZoom((z) => Math.min(3, z + 0.1))}
                      className="p-1.5 rounded hover:bg-soc-surface-3 text-slate-400"
                      aria-label="Zoom in"
                    >
                      <ZoomIn className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => setZoom(1)}
                      className="p-1.5 rounded hover:bg-soc-surface-3 text-slate-400"
                      aria-label="Fit"
                    >
                      <Maximize className="h-4 w-4" />
                    </button>
                    <button
                      onClick={reset}
                      className="p-1.5 rounded hover:bg-soc-surface-3 text-slate-400"
                      aria-label="Reset"
                    >
                      <RotateCcw className="h-4 w-4" />
                    </button>
                  </div>
                </div>

                <div
                  className="h-[520px] overflow-hidden relative cursor-grab active:cursor-grabbing bg-soc-surface grid-bg"
                  onMouseDown={handleMouseDown}
                  onMouseMove={handleMouseMove}
                  onMouseUp={handleMouseUp}
                  onMouseLeave={handleMouseUp}
                >
                  {layoutedNodes.length === 0 ? (
                    <EmptyState
                      icon={<Network className="h-8 w-8" />}
                      title="No attack nodes found."
                      message="No attack relationships or cases match your current filters."
                    />
                  ) : (
                    <svg
                      className="w-full h-full"
                      style={{
                        transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
                        transformOrigin: "center center",
                      }}
                    >
                      {/* Edges */}
                      {filteredEdges.map((e, i) => {
                        const s = layoutedNodes.find((n) => n.id === e.source);
                        const t = layoutedNodes.find((n) => n.id === e.target);
                        if (!s || !t) return null;
                        return (
                          <line
                            key={i}
                            x1={s.x}
                            y1={s.y}
                            x2={t.x}
                            y2={t.y}
                            stroke="#36516C"
                            strokeWidth={1.5}
                            strokeDasharray={e.type === "similar" ? "4 4" : undefined}
                          />
                        );
                      })}

                      {/* Nodes */}
                      {layoutedNodes.map((n) => {
                        const color = nodeColors[n.type] ?? "#94A3B8";
                        const isSelected = selectedNode?.id === n.id;
                        return (
                          <g
                            key={n.id}
                            transform={`translate(${n.x}, ${n.y})`}
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedNode(n);
                            }}
                            className="cursor-pointer"
                          >
                            <circle
                              r={isSelected ? 18 : 14}
                              fill={color}
                              stroke={isSelected ? "#2BB7A9" : "#1B3048"}
                              strokeWidth={isSelected ? 3 : 2}
                              className="transition-all duration-150 hover:opacity-80"
                            />
                            <text
                              y={24}
                              textAnchor="middle"
                              className="text-[0.625rem] fill-slate-300 font-mono pointer-events-none"
                            >
                              {n.value.length > 14 ? `${n.value.slice(0, 12)}…` : n.value}
                            </text>
                          </g>
                        );
                      })}
                    </svg>
                  )}
                </div>
              </Card>
            </div>

            {/* Node Detail & Legend */}
            <div className="space-y-4">
              <Card surface={2}>
                <p className="text-sm font-semibold text-slate-100 mb-3">Selected Node</p>
                {selectedNode ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono text-slate-500 uppercase">{selectedNode.type}</span>
                      <SeverityBadge severity={selectedNode.risk} />
                    </div>
                    <div>
                      <p className="text-xs text-slate-500">Value</p>
                      <p className="text-sm text-slate-200 font-mono break-all">{selectedNode.value}</p>
                    </div>
                    <div>
                      <p className="text-xs text-slate-500 mb-1">Relationships</p>
                      <div className="space-y-1">
                        {filteredEdges
                          .filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
                          .map((e, i) => {
                            const other = e.source === selectedNode.id ? e.target : e.source;
                            const otherNode = layoutedNodes.find((n) => n.id === other);
                            return (
                              <div
                                key={i}
                                className="text-xs text-slate-400 p-2 bg-soc-surface rounded border border-soc-border"
                              >
                                <span className="text-slate-500">{e.type}</span>:{" "}
                                <span className="font-mono text-slate-300">{otherNode?.value ?? other}</span>
                              </div>
                            );
                          })}
                      </div>
                    </div>
                  </div>
                ) : (
                  <EmptyState
                    icon={<Network className="h-8 w-8" />}
                    title="Select a node"
                    message="Click any node in the graph to inspect its relationships."
                  />
                )}
              </Card>

              {/* Legend */}
              <Card surface={2}>
                <p className="text-sm font-semibold text-slate-100 mb-3">Legend</p>
                <div className="space-y-2">
                  {Object.entries(nodeColors).map(([t, color]) => (
                    <div key={t} className="flex items-center gap-2">
                      <span className="h-3 w-3 rounded-full" style={{ backgroundColor: color }} />
                      <span className="text-xs text-slate-400 capitalize">{t}</span>
                    </div>
                  ))}
                  <div className="border-t border-soc-border pt-2 mt-2 space-y-2">
                    {(["critical", "high", "suspicious", "clean"] as Severity[]).map((s) => (
                      <div key={s} className="flex items-center gap-2">
                        <span className={`h-2 w-2 rounded-full ${SEVERITY_DOT[s]}`} />
                        <span className="text-xs text-slate-400 uppercase">{s}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </Card>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
