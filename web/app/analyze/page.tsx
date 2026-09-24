// web/app/analyze/page.tsx
"use client";

import { useState, useCallback, useEffect } from "react";
import { analyzeEmail, fetchLiveMail, fetchLiveMailEmail } from "@/lib/api";
import type { EmailDetail, EmailSummary } from "@/lib/types/soc";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { SeverityBadge, AnalysisStateBadge } from "@/components/ui/Badge";
import { SearchBar } from "@/components/ui/SearchBar";
import { SkeletonList, SkeletonCard } from "@/components/ui/Skeleton";
import { EmptyState, ErrorState } from "@/components/ui/States";
import { useToast } from "@/components/ui/Toast";
import { Header } from "@/components/Header";
import { formatDate } from "@/lib/constants";
import {
  Upload,
  Radio,
  AlertCircle,
  CheckCircle2,
  Mail,
  Search as SearchIcon,
} from "lucide-react";

type SourceMode = "upload" | "live";

export default function AnalyzeEmailPage() {
  const [source, setSource] = useState<SourceMode>("upload");
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<EmailDetail | null>(null);

  // Live mail state
  const [emails, setEmails] = useState<EmailSummary[]>([]);
  const [loadingEmails, setLoadingEmails] = useState(false);
  const [emailError, setEmailError] = useState(false);
  const [fetchLimit, setFetchLimit] = useState<number>(50);
  const [selectedEmail, setSelectedEmail] = useState<EmailSummary | null>(null);
  const [selectedActionLoading, setSelectedActionLoading] = useState(false);
  const [search, setSearch] = useState("");

  const { show } = useToast();

  const loadEmails = useCallback(() => {
    setLoadingEmails(true);
    setEmailError(false);
    fetchLiveMail(fetchLimit)
      .then(setEmails)
      .catch(() => setEmailError(true))
      .finally(() => setLoadingEmails(false));
  }, [fetchLimit]);

  useEffect(() => {
    if (source === "live") loadEmails();
  }, [source, loadEmails]);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 10 * 1024 * 1024) {
      show("error", "File exceeds 10MB maximum limit.");
      return;
    }

    setAnalyzing(true);
    setAnalysisResult(null);

    try {
      const result = await analyzeEmail(file);
      setAnalysisResult(result);
      show("success", "Analysis completed successfully.");
    } catch {
      show("error", "Failed to analyze email. Ensure it is a valid .eml file.");
    } finally {
      setAnalyzing(false);
    }
  };

  const inspectSelectedEmail = async () => {
    if (!selectedEmail) return;
    setSelectedActionLoading(true);
    try {
      const detail = await fetchLiveMailEmail(selectedEmail.uid);
      setAnalysisResult(detail);
      setSource("upload");
      show("success", `Loaded analysis for UID ${selectedEmail.uid}`);
    } catch {
      show("error", "Failed to load live email details.");
    } finally {
      setSelectedActionLoading(false);
    }
  };

  const filteredEmails = emails.filter((e) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return e.sender.toLowerCase().includes(q) || e.subject.toLowerCase().includes(q);
  });

  return (
    <div className="flex flex-col flex-1 min-w-0">
      <Header
        title="Analyze Email"
        description="Upload or select emails for forensic analysis"
      />

      <div className="p-4 lg:p-6 space-y-6 flex-1 animate-fade-in">
        {/* Source Selector */}
        <div className="flex items-center gap-2 border-b border-soc-border pb-3">
          <button
            onClick={() => setSource("upload")}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              source === "upload"
                ? "bg-accent/15 text-accent border border-accent/40"
                : "text-slate-400 hover:text-slate-200 hover:bg-soc-surface-2"
            }`}
          >
            <Upload className="h-4 w-4" />
            <span>📤 Upload Email</span>
          </button>
          <button
            onClick={() => setSource("live")}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              source === "live"
                ? "bg-accent/15 text-accent border border-accent/40"
                : "text-slate-400 hover:text-slate-200 hover:bg-soc-surface-2"
            }`}
          >
            <Radio className="h-4 w-4" />
            <span>📬 Select from Live Mail</span>
          </button>
        </div>

        {source === "upload" && (
          <div className="space-y-6">
            {/* File Upload Box */}
            <Card surface={2}>
              <div className="border-2 border-dashed border-soc-border-light rounded-lg p-8 text-center hover:border-accent transition-colors relative">
                <input
                  type="file"
                  accept=".eml,message/rfc822"
                  onChange={handleFileUpload}
                  disabled={analyzing}
                  className="absolute inset-0 opacity-0 cursor-pointer disabled:cursor-not-allowed"
                />
                <div className="flex flex-col items-center justify-center space-y-3 pointer-events-none">
                  <div className="p-3 rounded-full bg-soc-surface-3 text-accent">
                    <Upload className="h-6 w-6" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-slate-200">
                      {analyzing ? "Analyzing email forensic headers..." : "Drop .eml file here or click to browse"}
                    </p>
                    <p className="text-xs text-slate-500 mt-1">RFC822 email format up to 10MB</p>
                  </div>
                </div>
              </div>
            </Card>

            {/* Analysis Result */}
            {analyzing && <SkeletonCard lines={8} />}

            {analysisResult && (
              <Card surface={2} className="space-y-4">
                <CardHeader
                  title="Forensic Analysis Result"
                  subtitle={`Case: ${analysisResult.uid}`}
                  action={<SeverityBadge severity={analysisResult.risk_status} size="md" />}
                />

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Email Metadata</h4>
                    <dl className="text-xs space-y-1.5">
                      <div className="flex gap-2">
                        <dt className="text-slate-500 w-24 shrink-0">Sender:</dt>
                        <dd className="text-slate-200 font-mono truncate">{analysisResult.sender}</dd>
                      </div>
                      <div className="flex gap-2">
                        <dt className="text-slate-500 w-24 shrink-0">Subject:</dt>
                        <dd className="text-slate-200 truncate">{analysisResult.subject}</dd>
                      </div>
                      <div className="flex gap-2">
                        <dt className="text-slate-500 w-24 shrink-0">Date:</dt>
                        <dd className="text-slate-200">{formatDate(analysisResult.date)}</dd>
                      </div>
                      <div className="flex gap-2">
                        <dt className="text-slate-500 w-24 shrink-0">Risk Score:</dt>
                        <dd className="text-slate-200 font-mono font-bold">{analysisResult.risk_score} / 100</dd>
                      </div>
                    </dl>
                  </div>

                  <div>
                    <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">Authentication</h4>
                    <div className="flex gap-3">
                      {(["spf", "dkim", "dmarc"] as const).map((auth) => {
                        const val = analysisResult.authentication[auth];
                        const pass = val === "pass";
                        return (
                          <div key={auth} className="flex items-center gap-1.5 text-xs bg-soc-surface px-2.5 py-1.5 rounded border border-soc-border">
                            {pass ? (
                              <CheckCircle2 className="h-3.5 w-3.5 text-status-connected" />
                            ) : (
                              <AlertCircle className="h-3.5 w-3.5 text-status-error" />
                            )}
                            <span className="uppercase text-slate-400 font-mono">{auth}</span>
                            <span className={`font-semibold uppercase ${pass ? "text-status-connected" : "text-status-error"}`}>
                              {val}
                            </span>
                          </div>
                        );
                      })}
                    </div>

                    {analysisResult.urls.length > 0 && (
                      <div className="mt-3">
                        <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-1">
                          Extracted URLs ({analysisResult.urls.length})
                        </h4>
                        <div className="space-y-1 max-h-24 overflow-y-auto scrollbar-thin">
                          {analysisResult.urls.map((url, i) => (
                            <p key={i} className="text-xs text-slate-300 font-mono truncate bg-soc-surface p-1 rounded">
                              {url}
                            </p>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </Card>
            )}
          </div>
        )}

        {source === "live" && (
          <div className="space-y-4">
            {/* Fetch Limit Selector */}
            <div className="flex items-center gap-3 flex-wrap">
              <span className="text-xs text-slate-400 font-medium">Fetch Limit:</span>
              <div className="flex items-center gap-1">
                {[50, 100, 200].map((limit) => (
                  <button
                    key={limit}
                    onClick={() => setFetchLimit(limit)}
                    className={`text-xs font-medium px-3 py-1.5 rounded-md border transition-colors ${
                      fetchLimit === limit
                        ? "bg-accent/15 text-accent border-accent/40"
                        : "bg-soc-surface-2 text-slate-400 border-soc-border-light hover:text-slate-200"
                    }`}
                  >
                    {limit}
                  </button>
                ))}
              </div>
              <Button variant="ghost" size="sm" onClick={loadEmails}>
                Refresh
              </Button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* Email List — single scrollable container with overflow-y-auto */}
              <div className="lg:col-span-2">
                <Card surface={2} noPadding>
                  <div className="p-3 border-b border-soc-border">
                    <SearchBar
                      value={search}
                      onChange={setSearch}
                      onClear={() => setSearch("")}
                      placeholder="Filter by sender or subject..."
                    />
                  </div>
                  <div className="max-h-[500px] overflow-y-auto scrollbar-thin">
                    {loadingEmails ? (
                      <div className="p-3">
                        <SkeletonList items={6} />
                      </div>
                    ) : emailError ? (
                      <ErrorState type="connection" onRetry={loadEmails} />
                    ) : filteredEmails.length === 0 ? (
                      <EmptyState
                        icon={<Mail className="h-8 w-8" />}
                        title="No emails found."
                        message={search ? "Try adjusting your filter." : "No live mail data available."}
                      />
                    ) : (
                      <div className="divide-y divide-soc-border">
                        {filteredEmails.map((email) => (
                          <button
                            key={email.uid}
                            onClick={() => setSelectedEmail(email)}
                            className={`flex items-center gap-3 w-full px-3 py-2.5 text-left hover:bg-soc-surface-2 transition-colors ${
                              selectedEmail?.uid === email.uid ? "bg-soc-surface-2 border-l-2 border-l-accent" : ""
                            }`}
                          >
                            <SeverityBadge severity={email.risk_status} />
                            <div className="flex-1 min-w-0">
                              <p className="text-sm text-slate-200 truncate">{email.sender}</p>
                              <p className="text-xs text-slate-400 truncate">{email.subject}</p>
                            </div>
                            <div className="text-right shrink-0">
                              <p className="text-xs text-slate-500">{formatDate(email.date)}</p>
                              <p className="text-[0.625rem] text-slate-600 font-mono mt-0.5">UID: {email.uid}</p>
                            </div>
                            <div className="shrink-0">
                              {email.analysis_state === "not_analyzed" ? (
                                <span className="text-xs text-slate-500">Not analyzed</span>
                              ) : (
                                <AnalysisStateBadge state={email.analysis_state} />
                              )}
                            </div>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </Card>
              </div>

              {/* Selected Email Details */}
              <div>
                <Card surface={2}>
                  <CardHeader title="Selected Email" subtitle="Metadata & analysis preview" />
                  {selectedEmail ? (
                    <div className="space-y-3">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={selectedEmail.risk_status} />
                        <AnalysisStateBadge state={selectedEmail.analysis_state} />
                      </div>
                      <dl className="space-y-2 text-sm">
                        <div>
                          <dt className="text-xs text-slate-500">Sender</dt>
                          <dd className="text-slate-200 truncate font-mono text-xs">{selectedEmail.sender}</dd>
                        </div>
                        <div>
                          <dt className="text-xs text-slate-500">Subject</dt>
                          <dd className="text-slate-200 text-xs">{selectedEmail.subject}</dd>
                        </div>
                        <div>
                          <dt className="text-xs text-slate-500">Date</dt>
                          <dd className="text-slate-200 text-xs">{formatDate(selectedEmail.date)}</dd>
                        </div>
                        <div>
                          <dt className="text-xs text-slate-500">UID</dt>
                          <dd className="text-slate-300 font-mono text-xs">UID: {selectedEmail.uid}</dd>
                        </div>
                      </dl>
                      <div className="flex gap-2 pt-2 border-t border-soc-border">
                        <Button
                          variant="primary"
                          size="sm"
                          className="flex-1"
                          onClick={inspectSelectedEmail}
                          loading={selectedActionLoading}
                        >
                          <SearchIcon className="h-3.5 w-3.5" /> Analyze
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <EmptyState
                      icon={<Mail className="h-8 w-8" />}
                      title="Select an email"
                      message="Click an email from the list to inspect details."
                    />
                  )}
                </Card>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
