// web/app/live-mail/page.tsx
"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import {
  fetchLiveMail,
  fetchLiveMailFeed,
  fetchLiveMailTelemetry,
  fetchLiveMailEmail,
  disconnectMailbox,
  testMailboxConnection,
  pollLiveMailNow,
} from "@/lib/api";
import type { EmailSummary, EmailDetail, LiveMailTelemetry } from "@/lib/types/soc";
import { Card, CardHeader } from "@/components/ui/Card";
import { SeverityBadge, AnalysisStateBadge } from "@/components/ui/Badge";
import { SkeletonKPI, SkeletonList } from "@/components/ui/Skeleton";
import { ErrorState } from "@/components/ui/States";
import { Header } from "@/components/Header";
import { ConfirmDialog } from "@/components/ui/Modal";
import { ConnectMailboxModal } from "@/components/live-mail/ConnectMailboxModal";
import { formatDate, formatRelative, FETCH_LIMITS } from "@/lib/constants";
import {
  Server,
  Mail,
  MailCheck,
  ShieldAlert,
  AlertOctagon,
  Copy,
  AlertTriangle,
  Hash,
  Clock,
  RefreshCw,
  Plus,
  Unplug,
  CheckCircle2,
  XCircle,
  Loader2,
  ShieldCheck,
} from "lucide-react";

export default function LiveMailPage() {
  const [telemetry, setTelemetry] = useState<LiveMailTelemetry | null>(null);
  const [emails, setEmails] = useState<EmailSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [fetchLimit, setFetchLimit] = useState<number>(50);
  const [selected, setSelected] = useState<EmailDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Modals & Action States
  const [connectModalOpen, setConnectModalOpen] = useState(false);
  const [disconnectDialogOpen, setDisconnectDialogOpen] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [pollingNow, setPollingNow] = useState(false);
  const [actionFeedback, setActionFeedback] = useState<{ type: "success" | "error"; message: string } | null>(null);

  const isFetchingRef = useRef(false);
  const isAutoPollingRef = useRef(false);
  const lastRealPollRef = useRef<number>(0);

  const sortNewestFirst = (list: EmailSummary[]): EmailSummary[] => {
    return [...list].sort((a, b) => {
      const timeA = Date.parse(a.date);
      const timeB = Date.parse(b.date);
      if (!isNaN(timeA) && !isNaN(timeB) && timeA !== timeB) return timeB - timeA;
      return (Number(b.uid) || 0) - (Number(a.uid) || 0);
    });
  };

  const load = useCallback(async (isInitial = false) => {
    if (isFetchingRef.current) return;
    isFetchingRef.current = true;
    if (isInitial) {
      setLoading(true);
      setError(false);
    }
    try {
      const feed = await fetchLiveMailFeed(fetchLimit);
      setTelemetry(feed.telemetry);
      setEmails(sortNewestFirst(feed.emails));

      // Auto-trigger real IMAP poll when stale (>30s since last real poll)
      // This runs inside the same 2s loop — no duplicate intervals
      const now = Date.now();
      if (
        !isAutoPollingRef.current &&
        !pollingNow &&
        now - lastRealPollRef.current > 30000
      ) {
        isAutoPollingRef.current = true;
        lastRealPollRef.current = now;
        pollLiveMailNow()
          .catch(() => {
            // Silent: auto-poll failures do not surface to user
          })
          .finally(() => {
            isAutoPollingRef.current = false;
          });
      }
    } catch {
      if (isInitial) setError(true);
    } finally {
      if (isInitial) setLoading(false);
      isFetchingRef.current = false;
    }
  }, [fetchLimit, pollingNow]);

  const handlePollNow = async () => {
    setPollingNow(true);
    try {
      await pollLiveMailNow();
      lastRealPollRef.current = Date.now();
      const feed = await fetchLiveMailFeed(fetchLimit);
      setTelemetry(feed.telemetry);
      setEmails(sortNewestFirst(feed.emails));
      setActionFeedback({
        type: "success",
        message: "Live mail polled successfully. Mailbox telemetry synchronized.",
      });
    } catch (err: any) {
      setActionFeedback({
        type: "error",
        message: err?.message || "Failed to trigger live mail poll.",
      });
    } finally {
      setPollingNow(false);
    }
  };

  // Single unified 2-second polling loop
  // - Reads cached DB state every 2s (fast, no IMAP)
  // - Conditionally triggers real IMAP poll when >30s stale (automatic Gmail detection)
  // - No duplicate intervals, cleanup on unmount
  useEffect(() => {
    load(true);
    const interval = setInterval(() => {
      load(false);
    }, 2000);
    return () => clearInterval(interval);
  }, [load]);

  const inspectEmail = async (uid: string) => {
    setDetailLoading(true);
    try {
      const detail = await fetchLiveMailEmail(uid);
      setSelected(detail);
    } catch {
      setSelected(null);
    } finally {
      setDetailLoading(false);
    }
  };

  const handleDisconnect = async () => {
    setDisconnecting(true);
    try {
      await disconnectMailbox();
      setDisconnectDialogOpen(false);
      setActionFeedback({
        type: "success",
        message: "Mailbox disconnected and monitoring stopped.",
      });
      load();
    } catch (err: any) {
      setActionFeedback({
        type: "error",
        message: err?.message || "Failed to disconnect mailbox.",
      });
    } finally {
      setDisconnecting(false);
    }
  };

  const isConnected = telemetry?.connected === true && telemetry?.state !== "NO_MAILBOX";
  const mailboxState = telemetry?.state || (isConnected ? "ACTIVE" : "NO_MAILBOX");

  const cards = [
    { label: "Emails Arrived", value: telemetry?.emails_arrived, icon: Mail },
    { label: "Emails Analysed", value: telemetry?.emails_analysed, icon: MailCheck },
    { label: "Threats Detected", value: telemetry?.threats_detected, icon: ShieldAlert },
    { label: "High / Critical", value: telemetry?.high_critical, icon: AlertOctagon },
    { label: "Duplicates", value: telemetry?.duplicates, icon: Copy },
    { label: "Processing Errors", value: telemetry?.processing_errors, icon: AlertTriangle },
    { label: "Last UID", value: telemetry?.last_uid, icon: Hash, mono: true },
    { label: "Last Poll", value: telemetry?.last_poll ? formatRelative(telemetry.last_poll) : "—", icon: Clock },
  ];

  return (
    <div className="flex flex-col flex-1 min-w-0">
      <Header
        title="Live Mail Analysis"
        description="Autonomous Gmail IMAP threat monitoring and real-time ingestion"
        actions={
          <div className="flex items-center gap-2">
            {!isConnected ? (
              <button
                onClick={() => setConnectModalOpen(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-accent text-white hover:bg-accent-hover transition-colors shadow-sm"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>Connect Mailbox</span>
              </button>
            ) : (
              <button
                onClick={() => setConnectModalOpen(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-soc-surface-2 text-slate-300 hover:text-white hover:bg-soc-surface-3 transition-colors border border-soc-border"
              >
                <RefreshCw className="h-3.5 w-3.5" />
                <span>Reconfigure</span>
              </button>
            )}
            <button
              onClick={handlePollNow}
              disabled={pollingNow || !isConnected}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-soc-surface-2 text-slate-300 hover:text-white hover:bg-soc-surface-3 transition-colors border border-soc-border disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${pollingNow ? "animate-spin" : ""}`} />
              <span>{pollingNow ? "Polling..." : "Poll Now"}</span>
            </button>
          </div>
        }
      />

      <div className="p-4 lg:p-6 space-y-6 flex-1 animate-fade-in">
        {/* Banner Feedback */}
        {actionFeedback && (
          <div
            className={`flex items-center justify-between p-3 rounded-md text-xs border ${
              actionFeedback.type === "success"
                ? "bg-status-connected/10 border-status-connected/30 text-status-connected"
                : "bg-severity-critical/10 border-severity-critical/30 text-red-300"
            }`}
          >
            <div className="flex items-center gap-2">
              {actionFeedback.type === "success" ? (
                <CheckCircle2 className="h-4 w-4" />
              ) : (
                <XCircle className="h-4 w-4" />
              )}
              <span>{actionFeedback.message}</span>
            </div>
            <button
              onClick={() => setActionFeedback(null)}
              className="text-slate-400 hover:text-slate-200"
            >
              Dismiss
            </button>
          </div>
        )}

        {loading ? (
          <div className="space-y-6">
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {Array.from({ length: 8 }).map((_, i) => (
                <SkeletonKPI key={i} />
              ))}
            </div>
            <SkeletonList items={8} />
          </div>
        ) : error ? (
          <ErrorState type="connection" onRetry={load} />
        ) : !isConnected ? (
          /* ========================================================= */
          /* NOT CONNECTED STATE (Strictly required when no mailbox linked) */
          /* ========================================================= */
          <div className="space-y-6">
            {/* Status Banner */}
            <Card surface={2}>
              <div className="flex items-center justify-between flex-wrap gap-3">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-md bg-rose-500/10 text-rose-400 border border-rose-500/20">
                    <Unplug className="h-5 w-5" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-semibold text-slate-100">Live Mail Analysis Status</p>
                      <span className="flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                        <span className="h-1.5 w-1.5 rounded-full bg-rose-400" />
                        NOT CONNECTED
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5">
                      No mailbox is linked to this account.
                    </p>
                  </div>
                </div>

                <button
                  onClick={() => setConnectModalOpen(true)}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-md text-xs font-semibold text-white bg-accent hover:bg-accent-hover transition-colors shadow-md shadow-accent/20"
                >
                  <Plus className="h-4 w-4" />
                  <span>Connect Mailbox</span>
                </button>
              </div>
            </Card>

            {/* Empty State Box */}
            <Card surface={2} className="text-center py-14 px-6 border-dashed">
              <div className="max-w-md mx-auto space-y-4">
                <div className="h-14 w-14 rounded-full bg-soc-surface-3 text-slate-400 flex items-center justify-center mx-auto border border-soc-border">
                  <Mail className="h-7 w-7 text-accent" />
                </div>
                <div>
                  <h3 className="text-base font-semibold text-slate-100">
                    No mailbox is linked to this account.
                  </h3>
                  <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                    Connect your Gmail mailbox with a dedicated 16-character Google App Password. EMAILSHIELD Sentinel will autonomously monitor incoming emails via secure TLS IMAP (imap.gmail.com:993) and run deep forensic risk analysis.
                  </p>
                </div>
                <div className="pt-2">
                  <button
                    onClick={() => setConnectModalOpen(true)}
                    className="inline-flex items-center gap-2 px-5 py-2.5 rounded-md text-xs font-semibold text-white bg-accent hover:bg-accent-hover transition-colors shadow-lg shadow-accent/25"
                  >
                    <Plus className="h-4 w-4" />
                    <span>+ Connect Mailbox</span>
                  </button>
                </div>
                <div className="pt-4 border-t border-soc-border/60 text-[11px] text-slate-500 flex items-center justify-center gap-4">
                  <span>Host: imap.gmail.com:993</span>
                  <span>•</span>
                  <span>TLS Mandatory</span>
                  <span>•</span>
                  <span>Worker RSA-OAEP Encrypted</span>
                </div>
              </div>
            </Card>
          </div>
        ) : (
          /* ========================================================= */
          /* CONNECTED / ACTIVE STATE */
          /* ========================================================= */
          <>
            {/* Worker & Mailbox Status Banner */}
            <Card surface={2}>
              <div className="flex items-center justify-between flex-wrap gap-4">
                <div className="flex items-center gap-3.5">
                  <div className="p-2.5 rounded-md bg-status-connected/10 text-status-connected border border-status-connected/20">
                    <Server className="h-5 w-5" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="text-sm font-semibold text-slate-100">
                        {telemetry?.mailbox?.email_address
                          ? `Monitoring ${telemetry.mailbox.email_address}`
                          : "Live Mail Analysis Worker"}
                      </p>
                      {mailboxState === "ACTIVE" ? (
                        <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-semibold bg-status-connected/15 text-status-connected border border-status-connected/30">
                          <span className="h-1.5 w-1.5 rounded-full bg-status-connected animate-pulse" />
                          ACTIVE
                        </span>
                      ) : mailboxState === "WORKER_ERROR" ? (
                        <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-semibold bg-severity-critical/15 text-severity-critical border border-severity-critical/30">
                          <span className="h-1.5 w-1.5 rounded-full bg-severity-critical" />
                          WORKER ERROR
                        </span>
                      ) : (
                        <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">
                          <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
                          CONNECTED (STANDBY)
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-400 mt-1">
                      Gmail IMAP (imap.gmail.com:993) · Autonomous polling daemon active
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setConnectModalOpen(true)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-soc-surface text-slate-300 hover:text-white hover:bg-soc-surface-3 transition-colors border border-soc-border"
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                    <span>Change Credentials</span>
                  </button>
                  <button
                    onClick={() => setDisconnectDialogOpen(true)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-severity-critical/10 text-rose-300 hover:bg-severity-critical/20 hover:text-white transition-colors border border-severity-critical/30"
                  >
                    <Unplug className="h-3.5 w-3.5" />
                    <span>Disconnect</span>
                  </button>
                </div>
              </div>
            </Card>

            {/* Telemetry Cards */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {cards.map((card) => {
                const Icon = card.icon;
                const val = card.value ?? 0;
                return (
                  <Card key={card.label} surface={2}>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-xs text-slate-400 font-medium">{card.label}</p>
                        <p className={`text-2xl font-bold text-slate-100 mt-1 ${card.mono ? "font-mono" : ""}`}>
                          {typeof val === "number" ? val.toLocaleString("en-IN") : val}
                        </p>
                      </div>
                      <div className="p-2 rounded-lg bg-soc-surface-3 text-slate-400">
                        <Icon className="h-4 w-4" />
                      </div>
                    </div>
                  </Card>
                );
              })}
            </div>

            {/* Email List */}
            <Card surface={2} noPadding>
              <div className="p-4 border-b border-soc-border">
                <div className="flex items-center justify-between flex-wrap gap-3">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-100">Live Mail Email Stream</h3>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Newest first · {emails.length} emails loaded
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-400">Limit:</span>
                    {FETCH_LIMITS.map((limit) => (
                      <button
                        key={limit}
                        onClick={() => setFetchLimit(limit)}
                        className={`text-xs font-medium px-2.5 py-1 rounded-md border transition-colors ${
                          fetchLimit === limit
                            ? "bg-accent/15 text-accent border-accent/40"
                            : "bg-soc-surface-2 text-slate-400 border-soc-border-light hover:text-slate-200"
                        }`}
                      >
                        {limit}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              <div className="max-h-[500px] overflow-y-auto scrollbar-thin">
                {emails.length === 0 ? (
                  <div className="py-12 text-center">
                    <Mail className="h-8 w-8 text-slate-500 mx-auto mb-2" />
                    <p className="text-sm font-medium text-slate-300">No emails ingested yet.</p>
                    <p className="text-xs text-slate-500 mt-1">
                      Sentinel worker daemon is active and waiting for new emails in your Gmail INBOX.
                    </p>
                  </div>
                ) : (
                  <table className="w-full">
                    <thead className="sticky top-0 bg-soc-surface-2 z-10">
                      <tr className="text-left text-xs text-slate-500 border-b border-soc-border">
                        <th className="px-3 py-2 font-medium">Risk</th>
                        <th className="px-3 py-2 font-medium">Sender</th>
                        <th className="px-3 py-2 font-medium hidden md:table-cell">Subject</th>
                        <th className="px-3 py-2 font-medium hidden lg:table-cell">Date</th>
                        <th className="px-3 py-2 font-medium hidden lg:table-cell">UID</th>
                        <th className="px-3 py-2 font-medium">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-soc-border">
                      {emails.map((email) => (
                        <tr
                          key={email.uid}
                          onClick={() => inspectEmail(email.uid)}
                          className="hover:bg-soc-surface-2 transition-colors cursor-pointer text-sm"
                        >
                          <td className="px-3 py-2">
                            <SeverityBadge severity={email.risk_status} />
                          </td>
                          <td className="px-3 py-2 text-slate-200 truncate max-w-[200px] font-mono text-xs">
                            {email.sender}
                          </td>
                          <td className="px-3 py-2 text-slate-300 truncate max-w-[250px] hidden md:table-cell">
                            {email.subject}
                          </td>
                          <td className="px-3 py-2 text-xs text-slate-500 hidden lg:table-cell whitespace-nowrap">
                            {formatDate(email.date)}
                          </td>
                          <td className="px-3 py-2 text-xs text-slate-500 font-mono hidden lg:table-cell">
                            {email.uid}
                          </td>
                          <td className="px-3 py-2">
                            <AnalysisStateBadge state={email.analysis_state} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </Card>

            {/* Selected Email Evidence Drawer */}
            {(detailLoading || selected) && (
              <Card surface={2}>
                <CardHeader
                  title="Selected Email Evidence"
                  subtitle="Read-only inspection from Live Mail"
                  action={selected ? <SeverityBadge severity={selected.risk_status} /> : undefined}
                />
                {detailLoading ? (
                  <div className="space-y-2">
                    <div className="skeleton h-4 w-2/3" />
                    <div className="skeleton h-4 w-1/2" />
                    <div className="skeleton h-20 w-full" />
                  </div>
                ) : selected ? (
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                    <div className="lg:col-span-2">
                      <p className="text-sm font-semibold text-slate-200">{selected.subject}</p>
                      <p className="text-xs text-slate-500 mt-1 font-mono">
                        {selected.sender} · {formatDate(selected.date)}
                      </p>
                      <p className="mt-4 text-xs text-slate-300 font-mono whitespace-pre-wrap leading-relaxed bg-soc-surface p-3 rounded border border-soc-border">
                        {selected.body_preview || "No body preview available."}
                      </p>
                    </div>
                    <div className="rounded-md border border-soc-border bg-soc-surface p-3">
                      <p className="ops-eyebrow mb-2">Authentication</p>
                      <div className="space-y-2 text-xs">
                        {Object.entries(selected.authentication).map(([key, value]) => (
                          <div key={key} className="flex justify-between gap-3">
                            <span className="text-slate-500 uppercase font-mono">{key}</span>
                            <span
                              className={`font-semibold uppercase ${
                                value === "pass" ? "text-status-connected" : "text-status-error"
                              }`}
                            >
                              {value}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : null}
              </Card>
            )}
          </>
        )}
      </div>

      {/* Connect Mailbox Modal */}
      <ConnectMailboxModal
        open={connectModalOpen}
        onClose={() => setConnectModalOpen(false)}
        onSuccess={() => {
          setActionFeedback({
            type: "success",
            message: "Gmail mailbox connected successfully. Live Mail monitoring active.",
          });
          load();
        }}
      />

      {/* Disconnect Mailbox Confirmation */}
      <ConfirmDialog
        open={disconnectDialogOpen}
        onClose={() => setDisconnectDialogOpen(false)}
        onConfirm={handleDisconnect}
        title="Disconnect Mailbox"
        message="Are you sure you want to disconnect this mailbox? Sentinel Live Mail monitoring will be immediately halted until you reconnect."
        confirmLabel="Disconnect Mailbox"
        danger
        loading={disconnecting}
      />
    </div>
  );
}
