// web/app/reports/page.tsx
"use client";

import { useEffect, useState, useCallback } from "react";
import { fetchReports, generateReport } from "@/lib/api";
import type { ReportSummary } from "@/lib/types/soc";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { SkeletonList } from "@/components/ui/Skeleton";
import { EmptyState, ErrorState } from "@/components/ui/States";
import { useToast } from "@/components/ui/Toast";
import { Header } from "@/components/Header";
import { formatDate } from "@/lib/constants";
import {
  FileText,
  Download,
  Loader2,
  FileCheck,
  ShieldCheck,
  AlertCircle,
  RefreshCw,
} from "lucide-react";

const REPORT_TYPES = ["PDF", "JSON", "CSV", "BSA"] as const;

export default function ReportsPage() {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [generating, setGenerating] = useState<string | null>(null);
  const { show } = useToast();

  const load = useCallback(() => {
    setLoading(true);
    setError(false);
    fetchReports()
      .then(setReports)
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleGenerate = async (investigationId: string, type: string) => {
    const key = `${investigationId}-${type}`;
    setGenerating(key);
    try {
      const blob = await generateReport(investigationId, type);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${investigationId}-${type}.${type.toLowerCase() === "pdf" ? "html" : type.toLowerCase()}`;
      a.click();
      URL.revokeObjectURL(url);
      show("success", `${type} forensic report exported successfully.`);
    } catch {
      show("error", `Failed to export ${type} report.`);
    } finally {
      setGenerating(null);
    }
  };

  // Group reports by investigation ID
  const grouped = reports.reduce<Record<string, ReportSummary[]>>((acc, r) => {
    if (!acc[r.investigation_id]) acc[r.investigation_id] = [];
    acc[r.investigation_id].push(r);
    return acc;
  }, {});

  return (
    <div className="flex flex-col flex-1 min-w-0">
      <Header
        title="Evidence & Reports"
        description="Evidence-preserving exports and Section 65B certified reports"
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
        {/* Certification Notice */}
        <Card surface={2}>
          <div className="flex items-center gap-3">
            <ShieldCheck className="h-5 w-5 text-status-connected shrink-0" />
            <div>
              <p className="text-sm font-semibold text-slate-100">
                Section 65B Indian Evidence Act (BSA Section 63) Certified Exports
              </p>
              <p className="text-xs text-slate-400 mt-0.5">
                All generated reports preserve RFC822 forensic headers, cryptographic hash chains, and immutable SHA-256 digests.
              </p>
            </div>
          </div>
        </Card>

        {loading ? (
          <SkeletonList items={6} />
        ) : error ? (
          <ErrorState type="unavailable" onRetry={load} />
        ) : Object.keys(grouped).length === 0 ? (
          <EmptyState
            icon={<FileText className="h-8 w-8" />}
            title="No reports generated yet."
            message="Forensic reports will appear here once incident investigations are conducted."
          />
        ) : (
          <div className="space-y-4">
            {Object.entries(grouped).map(([invId, caseReports]) => (
              <Card key={invId} surface={2}>
                <CardHeader
                  title={invId}
                  subtitle={`${caseReports.length} report formats available`}
                />
                <div className="space-y-2">
                  {caseReports.map((report) => (
                    <div
                      key={report.id}
                      className="flex items-center justify-between p-3 bg-soc-surface border border-soc-border rounded-md hover:border-soc-border-light transition-colors"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <FileText className="h-4 w-4 text-accent shrink-0" />
                        <div>
                          <p className="text-sm font-medium text-slate-200">{report.type} Forensic Record</p>
                          <p className="text-xs text-slate-500 font-mono">{formatDate(report.created)}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-xs text-status-connected flex items-center gap-1">
                          <FileCheck className="h-3.5 w-3.5" /> Available
                        </span>
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => handleGenerate(report.investigation_id, report.type)}
                          loading={generating === `${report.investigation_id}-${report.type}`}
                        >
                          <Download className="h-3.5 w-3.5" /> Export
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Generate New */}
                <div className="flex items-center gap-2 mt-3 pt-3 border-t border-soc-border">
                  <span className="text-xs text-slate-500">Export format:</span>
                  {REPORT_TYPES.map((type) => (
                    <Button
                      key={type}
                      variant="ghost"
                      size="sm"
                      onClick={() => handleGenerate(invId, type)}
                      loading={generating === `${invId}-${type}`}
                    >
                      {type}
                    </Button>
                  ))}
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
