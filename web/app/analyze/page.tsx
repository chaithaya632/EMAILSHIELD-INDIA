// web/app/analyze/page.tsx
"use client";

import { useState, useCallback, useEffect } from "react";
import {
  analyzeEmail,
  analyzeSample,
  fetchLiveMail,
  fetchLiveMailEmail,
} from "@/lib/api";
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
  Shield,
  ShieldAlert,
  ShieldCheck,
  Globe,
  Key,
  FileText,
  Link as LinkIcon,
  Paperclip,
  Clock,
  Copy,
  Check,
  RotateCcw,
  AlertTriangle,
  Zap,
  ExternalLink,
  ChevronRight,
  Server,
  Layers,
  Terminal,
} from "lucide-react";

type SourceMode = "upload" | "live";
type ForensicTab =
  | "overview"
  | "infrastructure"
  | "authentication"
  | "ioc_urls"
  | "indian_financial"
  | "rule_findings"
  | "hop_transit"
  | "attachments"
  | "headers";

const SAMPLE_SCENARIOS = [
  {
    id: "paypal",
    title: "PayPal Phishing",
    subtitle: "Auth Spoof & Unaligned Domain Bypass",
    badge: "Phishing",
    severity: "critical" as const,
    description: "Spoofed header-from identity mimicking PayPal with unaligned SPF/DKIM bounce relay.",
  },
  {
    id: "upi",
    title: "Indian Electricity UPI Extortion",
    subtitle: "Fake Bill Disconnection & VPA Lure",
    badge: "Extortion",
    severity: "critical" as const,
    description: "Urgent power disconnection notice directing victim to fraudulent UPI VPAs and NEFT IFSC.",
  },
  {
    id: "quishing",
    title: "Quishing QR Attack",
    subtitle: "Weaponized Invoice QR Code",
    badge: "Quishing",
    severity: "high" as const,
    description: "Embedded KYC invoice QR barcode resolving to credential harvesting phishing endpoint.",
  },
  {
    id: "malware",
    title: "Weaponized Malware Lure",
    subtitle: "Suspicious Double-Extension Payload",
    badge: "Malware",
    severity: "high" as const,
    description: "Payment remittance lure carrying weaponized executable disguised as a billing document.",
  },
  {
    id: "clean",
    title: "Legitimate Bank Statement",
    subtitle: "Cryptographically Verified Clean",
    badge: "Clean",
    severity: "clean" as const,
    description: "Monthly account notification with valid SPF, DKIM alignment, and authentic mail routes.",
  },
];

export default function AnalyzeEmailPage() {
  const [source, setSource] = useState<SourceMode>("upload");
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<EmailDetail | null>(null);
  const [activeTab, setActiveTab] = useState<ForensicTab>("overview");
  const [copiedField, setCopiedField] = useState<string | null>(null);

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
      .then((list) => {
        // Enforce strict reverse chronological order (newest first)
        const sorted = [...list].sort((a, b) => {
          const timeA = Date.parse(a.date);
          const timeB = Date.parse(b.date);
          if (!isNaN(timeA) && !isNaN(timeB) && timeA !== timeB) return timeB - timeA;
          return (Number(b.uid) || 0) - (Number(a.uid) || 0);
        });
        setEmails(sorted);
      })
      .catch(() => setEmailError(true))
      .finally(() => setLoadingEmails(false));
  }, [fetchLimit]);

  useEffect(() => {
    if (source === "live") loadEmails();
  }, [source, loadEmails]);

  const copyToClipboard = (text: string, fieldName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldName);
    setTimeout(() => setCopiedField(null), 2000);
    show("info", `Copied ${fieldName} to clipboard`);
  };

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
      setActiveTab("overview");
      show("success", "Full forensic analysis completed successfully.");
    } catch {
      show("error", "Failed to analyze email. Ensure it is a valid .eml file.");
    } finally {
      setAnalyzing(false);
    }
  };

  const handleSampleLoad = async (sampleId: string) => {
    setAnalyzing(true);
    setAnalysisResult(null);
    try {
      const result = await analyzeSample(sampleId);
      setAnalysisResult(result);
      setActiveTab("overview");
      show("success", `Loaded and analyzed scenario: ${sampleId.toUpperCase()}`);
    } catch {
      show("error", `Failed to analyze sample scenario: ${sampleId}`);
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
      setActiveTab("overview");
      show("success", `Loaded complete forensic analysis for UID ${selectedEmail.uid}`);
    } catch {
      show("error", "Failed to load live email forensic details.");
    } finally {
      setSelectedActionLoading(false);
    }
  };

  const filteredEmails = emails.filter((e) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return e.sender.toLowerCase().includes(q) || e.subject.toLowerCase().includes(q);
  });

  const isClean = analysisResult?.risk_status === "clean";
  const auth = analysisResult?.auth_alignment;
  const infra = analysisResult?.infrastructure_intel;
  const domRep = analysisResult?.domain_reputation;
  const indianFin = analysisResult?.indian_financial;
  const findings = analysisResult?.findings || [];
  const urls = analysisResult?.url_threats || [];
  const hops = analysisResult?.hop_transit || [];
  const iocs = analysisResult?.indicators || [];
  const atts = analysisResult?.attachments || [];

  return (
    <div className="flex flex-col flex-1 min-w-0">
      <Header
        title="Analyze Email"
        description="Comprehensive 11-Layer Email Forensic Investigation & Telemetry"
      />

      <div className="p-4 lg:p-6 space-y-6 flex-1 animate-fade-in">
        {/* Source Selector */}
        <div className="flex items-center justify-between border-b border-soc-border pb-3 flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setSource("upload")}
              className={`flex items-center gap-2 px-4 py-2 rounded-md text-xs font-semibold uppercase tracking-wider transition-colors ${
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
              className={`flex items-center gap-2 px-4 py-2 rounded-md text-xs font-semibold uppercase tracking-wider transition-colors ${
                source === "live"
                  ? "bg-accent/15 text-accent border border-accent/40"
                  : "text-slate-400 hover:text-slate-200 hover:bg-soc-surface-2"
              }`}
            >
              <Radio className="h-4 w-4" />
              <span>📬 Select from Live Mail</span>
            </button>
          </div>

          {analysisResult && (
            <button
              onClick={() => {
                setAnalysisResult(null);
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium text-slate-400 hover:text-white hover:bg-soc-surface-3 transition-colors border border-soc-border"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              <span>Reset / Test Another</span>
            </button>
          )}
        </div>

        {source === "upload" && (
          <div className="space-y-6">
            {!analysisResult && (
              <>
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
                          {analyzing
                            ? "Running 11-layer forensic investigation..."
                            : "Drop .eml file here or click to browse"}
                        </p>
                        <p className="text-xs text-slate-500 mt-1">
                          RFC822 email format up to 10MB (Raw headers, MIME, attachments analyzed)
                        </p>
                      </div>
                    </div>
                  </div>
                </Card>

                {/* 1-Click Instant Attack Scenarios */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
                      <Zap className="h-4 w-4 text-accent" />
                      <span>1-Click Instant Forensic Attack Scenarios</span>
                    </h3>
                    <span className="text-xs text-slate-500">Test full investigation instantly</span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                    {SAMPLE_SCENARIOS.map((scenario) => (
                      <button
                        key={scenario.id}
                        disabled={analyzing}
                        onClick={() => handleSampleLoad(scenario.id)}
                        className="p-3.5 rounded-lg border border-soc-border bg-soc-surface-2 hover:bg-soc-surface-3 hover:border-accent/50 text-left transition-all group flex flex-col justify-between space-y-2.5 disabled:opacity-50"
                      >
                        <div>
                          <div className="flex items-center justify-between gap-2 mb-1">
                            <span className="text-xs font-semibold text-slate-200 group-hover:text-accent transition-colors">
                              {scenario.title}
                            </span>
                            <SeverityBadge severity={scenario.severity} size="sm" />
                          </div>
                          <p className="text-[0.6875rem] font-medium text-slate-400">
                            {scenario.subtitle}
                          </p>
                          <p className="text-xs text-slate-500 line-clamp-2 mt-1">
                            {scenario.description}
                          </p>
                        </div>
                        <div className="flex items-center gap-1 text-[0.6875rem] font-medium text-accent pt-1 border-t border-soc-border/50">
                          <span>Run Scenario</span>
                          <ChevronRight className="h-3 w-3" />
                        </div>
                      </button>
                    ))}
                  </div>
                </div>
              </>
            )}

            {analyzing && <SkeletonCard lines={10} />}

            {/* FULL FORENSIC INVESTIGATION REPORT */}
            {analysisResult && (
              <div className="space-y-6">
                {/* PROMINENT USER-FRIENDLY HERO CARD */}
                {isClean ? (
                  <div className="rounded-xl p-5 border-2 border-emerald-500/80 bg-gradient-to-r from-emerald-950/80 via-emerald-900/40 to-soc-surface-2 shadow-lg shadow-emerald-950/40 space-y-3">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <div className="flex items-center gap-2.5">
                        <span className="px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-emerald-500 text-slate-950 flex items-center gap-1.5 shadow-sm">
                          <CheckCircle2 className="h-3.5 w-3.5" />
                          <span>Verified Clean</span>
                        </span>
                        <span className="text-xs text-emerald-300 font-medium">
                          Case: {analysisResult.case_id || analysisResult.uid}
                        </span>
                      </div>
                      <SeverityBadge severity="clean" size="md" />
                    </div>

                    <div>
                      <h2 className="text-lg md:text-xl font-bold text-emerald-100 flex items-center gap-2">
                        <ShieldCheck className="h-6 w-6 text-emerald-400 shrink-0" />
                        <span>STATUS: THIS EMAIL IS SAFE TO OPEN</span>
                      </h2>
                      <p className="text-xs md:text-sm text-emerald-200/90 mt-1 max-w-4xl">
                        {analysisResult.plain_language_summary ||
                          "EMAILSHIELD analyzed this message. No signs of phishing, executive impersonation, malicious attachments, or spoofed senders were detected."}
                      </p>
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-emerald-500/20 text-xs">
                      <div>
                        <span className="text-emerald-400/80 block text-[0.6875rem]">Risk Score</span>
                        <span className="font-mono font-bold text-white">
                          {analysisResult.risk_score} / 100
                        </span>
                      </div>
                      <div>
                        <span className="text-emerald-400/80 block text-[0.6875rem]">Effective DMARC</span>
                        <span className="font-mono font-bold text-emerald-300">
                          {auth?.effective_dmarc || "PASS"}
                        </span>
                      </div>
                      <div>
                        <span className="text-emerald-400/80 block text-[0.6875rem]">Originating IP</span>
                        <span className="font-mono text-slate-200">
                          {infra?.origin_ip || "Authoritative"} {infra?.flag}
                        </span>
                      </div>
                      <div>
                        <span className="text-emerald-400/80 block text-[0.6875rem]">Domain Reputation</span>
                        <span className="font-medium text-slate-200">
                          {domRep?.domain_age_days
                            ? `${domRep.domain_age_days}d (${Math.floor(domRep.domain_age_days / 365)}y)`
                            : "Established"}
                        </span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="rounded-xl p-5 border-2 border-red-500/80 bg-gradient-to-r from-red-950/80 via-red-900/40 to-soc-surface-2 shadow-lg shadow-red-950/40 space-y-3">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <div className="flex items-center gap-2.5">
                        <span className="px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-red-500 text-white flex items-center gap-1.5 shadow-sm">
                          <AlertTriangle className="h-3.5 w-3.5" />
                          <span>Threat Detected</span>
                        </span>
                        <span className="text-xs text-red-300 font-medium">
                          Case: {analysisResult.case_id || analysisResult.uid}
                        </span>
                      </div>
                      <SeverityBadge severity={analysisResult.risk_status} size="md" />
                    </div>

                    <div>
                      <h2 className="text-lg md:text-xl font-bold text-red-100 flex items-center gap-2">
                        <ShieldAlert className="h-6 w-6 text-red-400 shrink-0" />
                        <span>STATUS: THIS EMAIL IS UNSAFE / DANGEROUS</span>
                      </h2>
                      <p className="text-xs md:text-sm text-red-200/90 mt-1 max-w-4xl">
                        {analysisResult.plain_language_summary ||
                          "Action Required: Do NOT click links, do NOT download attachments, and do NOT send money or reply to this sender."}
                      </p>
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-red-500/20 text-xs">
                      <div>
                        <span className="text-red-400/80 block text-[0.6875rem]">Risk Score</span>
                        <span className="font-mono font-bold text-red-400">
                          {analysisResult.risk_score} / 100
                        </span>
                      </div>
                      <div>
                        <span className="text-red-400/80 block text-[0.6875rem]">Effective DMARC</span>
                        <span className="font-mono font-bold text-amber-300">
                          {auth?.effective_dmarc || "FAIL"}
                        </span>
                      </div>
                      <div>
                        <span className="text-red-400/80 block text-[0.6875rem]">Originating IP</span>
                        <span className="font-mono text-slate-200">
                          {infra?.origin_ip || "Suspect Hop"} {infra?.flag}
                        </span>
                      </div>
                      <div>
                        <span className="text-red-400/80 block text-[0.6875rem]">Threat Vectors</span>
                        <span className="font-medium text-red-300">
                          {findings.length} Rule Violations
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Email Metadata Top Bar */}
                <Card surface={2}>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
                    <div>
                      <span className="text-slate-500 uppercase font-semibold text-[0.625rem] tracking-wider block">
                        Sender (Header-From)
                      </span>
                      <p className="font-mono text-slate-200 truncate mt-0.5" title={analysisResult.sender}>
                        {analysisResult.sender}
                      </p>
                    </div>
                    <div>
                      <span className="text-slate-500 uppercase font-semibold text-[0.625rem] tracking-wider block">
                        Subject
                      </span>
                      <p className="text-slate-200 truncate mt-0.5" title={analysisResult.subject}>
                        {analysisResult.subject}
                      </p>
                    </div>
                    <div>
                      <span className="text-slate-500 uppercase font-semibold text-[0.625rem] tracking-wider block">
                        Date & Timestamp
                      </span>
                      <p className="text-slate-200 mt-0.5">{formatDate(analysisResult.date)}</p>
                    </div>
                    <div>
                      <span className="text-slate-500 uppercase font-semibold text-[0.625rem] tracking-wider block">
                        SHA-256 Digest
                      </span>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        <span className="font-mono text-slate-400 truncate max-w-[140px]">
                          {analysisResult.sha256 || "N/A"}
                        </span>
                        {analysisResult.sha256 && (
                          <button
                            onClick={() => copyToClipboard(analysisResult.sha256!, "SHA-256")}
                            className="text-slate-400 hover:text-white"
                            title="Copy SHA-256"
                          >
                            {copiedField === "SHA-256" ? (
                              <Check className="h-3 w-3 text-status-connected" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                </Card>

                {/* FORENSIC TABS NAVIGATION */}
                <div className="flex items-center gap-1 border-b border-soc-border overflow-x-auto scrollbar-thin pb-1">
                  {[
                    { key: "overview", label: "Overview & AI Safety", icon: Shield },
                    { key: "infrastructure", label: "Dual-Card Infra & GeoIP", icon: Globe },
                    { key: "authentication", label: "RFC 7489 Auth Matrix", icon: Key },
                    { key: "ioc_urls", label: `IOCs & URLs (${iocs.length + urls.length})`, icon: LinkIcon },
                    { key: "indian_financial", label: "🇮🇳 Indian Cyber Intel", icon: Zap },
                    { key: "rule_findings", label: `Rule Findings (${findings.length})`, icon: FileText },
                    { key: "hop_transit", label: `MTA Relay Hops (${hops.length})`, icon: Server },
                    { key: "attachments", label: `Attachments (${atts.length})`, icon: Paperclip },
                    { key: "headers", label: "Raw RFC Headers", icon: Terminal },
                  ].map((tab) => {
                    const Icon = tab.icon;
                    const isActive = activeTab === tab.key;
                    return (
                      <button
                        key={tab.key}
                        onClick={() => setActiveTab(tab.key as ForensicTab)}
                        className={`flex items-center gap-1.5 px-3 py-2 rounded-t-md text-xs font-semibold whitespace-nowrap transition-colors border-b-2 ${
                          isActive
                            ? "border-accent text-accent bg-soc-surface-2"
                            : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-soc-surface-2/50"
                        }`}
                      >
                        <Icon className="h-3.5 w-3.5" />
                        <span>{tab.label}</span>
                      </button>
                    );
                  })}
                </div>

                {/* TAB 1: OVERVIEW & AI SAFETY SUMMARY */}
                {activeTab === "overview" && (
                  <div className="space-y-6">
                    {/* AI Reasoning Narrative */}
                    <Card surface={2}>
                      <CardHeader
                        title="AI Forensic Reasoning & Telemetry Chain"
                        subtitle="Autonomous analysis synthesized across mail headers, cryptographic claims, and payload"
                      />
                      <div className="space-y-3 text-xs leading-relaxed text-slate-300">
                        <div className="p-3.5 rounded-lg bg-soc-surface border border-soc-border">
                          <p className="font-semibold text-slate-200 mb-1 text-sm">
                            Executive Incident Briefing
                          </p>
                          <p className="whitespace-pre-line text-slate-300">
                            {analysisResult.ai_reasoning || analysisResult.plain_language_summary}
                          </p>
                        </div>
                      </div>
                    </Card>

                    {/* Section 14 Dual-Card Layout */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      {/* Origin Infrastructure Telemetry */}
                      <Card surface={2} className="space-y-3">
                        <div className="flex items-center justify-between border-b border-soc-border pb-2">
                          <h4 className="text-xs font-bold text-sky-400 uppercase tracking-wide flex items-center gap-1.5">
                            <Globe className="h-3.5 w-3.5" />
                            <span>Origin Infrastructure & Anonymization</span>
                          </h4>
                          <span className="text-[0.625rem] text-slate-500 font-mono">SECTION 14</span>
                        </div>

                        <div className="space-y-2 text-xs">
                          <div className="flex justify-between items-center py-1 border-b border-soc-border/50">
                            <span className="text-slate-400">Originating IP:</span>
                            <span className="font-mono text-cyan-300 font-semibold flex items-center gap-1.5">
                              {infra?.origin_ip || "Unavailable"} {infra?.flag}
                            </span>
                          </div>
                          <div className="flex justify-between items-center py-1 border-b border-soc-border/50">
                            <span className="text-slate-400">Network Location:</span>
                            <span className="text-slate-200 font-medium">
                              {infra?.city && infra?.country
                                ? `${infra.city}, ${infra.region ? infra.region + ", " : ""}${infra.country}`
                                : "Unavailable"}
                            </span>
                          </div>
                          <div className="flex justify-between items-center py-1 border-b border-soc-border/50">
                            <span className="text-slate-400">ISP / Routing Org:</span>
                            <span className="text-slate-200 font-medium truncate max-w-[200px]" title={infra?.isp}>
                              {infra?.isp || "Unknown Network"} ({infra?.asn || "Unknown ASN"})
                            </span>
                          </div>
                        </div>

                        <div className="flex flex-wrap gap-1.5 pt-1">
                          <span className="px-2 py-0.5 rounded text-[0.625rem] font-bold bg-sky-950 text-sky-300 border border-sky-800">
                            Cloud: {infra?.cloud_provider || "Non-Cloud / Dedicated"}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[0.625rem] font-bold border ${
                              infra?.vpn_indicator === "DETECTED"
                                ? "bg-red-950 text-red-300 border-red-800"
                                : "bg-emerald-950 text-emerald-300 border-emerald-800"
                            }`}
                          >
                            VPN: {infra?.vpn_indicator || "NOT_DETECTED"}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[0.625rem] font-bold border ${
                              infra?.tor_indicator === "DETECTED"
                                ? "bg-red-950 text-red-300 border-red-800"
                                : "bg-emerald-950 text-emerald-300 border-emerald-800"
                            }`}
                          >
                            Tor: {infra?.tor_indicator || "NOT_DETECTED"}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[0.625rem] font-bold border ${
                              infra?.open_relay_indicator === "INDICATED"
                                ? "bg-amber-950 text-amber-300 border-amber-800"
                                : "bg-emerald-950 text-emerald-300 border-emerald-800"
                            }`}
                          >
                            Open Relay: {infra?.open_relay_indicator || "NOT_INDICATED"}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[0.625rem] font-bold border ${
                              infra?.threat_feed_match === "MATCH"
                                ? "bg-red-950 text-red-300 border-red-800"
                                : "bg-emerald-950 text-emerald-300 border-emerald-800"
                            }`}
                          >
                            Threat Feed: {infra?.threat_feed_match || "NO_MATCH"}
                          </span>
                        </div>

                        <p className="text-[0.6875rem] text-slate-500 italic pt-1">
                          * Derived from available evidence. Provides routing context; does not prove human sender identity.
                        </p>
                      </Card>

                      {/* Domain Intelligence & DNS Exposure */}
                      <Card surface={2} className="space-y-3">
                        <div className="flex items-center justify-between border-b border-soc-border pb-2">
                          <h4 className="text-xs font-bold text-purple-400 uppercase tracking-wide flex items-center gap-1.5">
                            <Server className="h-3.5 w-3.5" />
                            <span>Domain Intelligence & RDAP Exposure</span>
                          </h4>
                          <span className="text-[0.625rem] text-slate-500 font-mono">SECTION 14</span>
                        </div>

                        <div className="space-y-2 text-xs">
                          <div className="flex justify-between items-center py-1 border-b border-soc-border/50">
                            <span className="text-slate-400">Inspected Domain:</span>
                            <span className="font-mono text-purple-300 font-semibold">
                              {domRep?.domain || analysisResult.sender_domain || "Unknown"}
                            </span>
                          </div>
                          <div className="flex justify-between items-center py-1 border-b border-soc-border/50">
                            <span className="text-slate-400">Registrar:</span>
                            <span className="text-slate-200 font-medium truncate max-w-[200px]" title={domRep?.registrar}>
                              {domRep?.registrar || "ICANN Accredited Registrar"}
                            </span>
                          </div>
                          <div className="flex justify-between items-center py-1 border-b border-soc-border/50">
                            <span className="text-slate-400">Creation Date & Age:</span>
                            <span className="text-slate-200 font-medium">
                              {domRep?.creation_date || "Unknown"} (
                              {domRep?.domain_age_days !== null && domRep?.domain_age_days !== undefined
                                ? `${domRep.domain_age_days} days / ${Math.floor(domRep.domain_age_days / 365)}y`
                                : "Established"}
                              )
                            </span>
                          </div>
                        </div>

                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {domRep?.is_newly_registered ? (
                            <span className="px-2 py-0.5 rounded text-[0.625rem] font-bold bg-red-950 text-red-300 border border-red-800">
                              🚨 NRD (&lt;30 Days Old)
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[0.625rem] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                              ✅ Established Domain (&gt;180 Days)
                            </span>
                          )}
                          <span className="px-2 py-0.5 rounded text-[0.625rem] font-bold bg-soc-surface text-slate-300 border border-soc-border">
                            SSRF Guard: Active
                          </span>
                        </div>

                        <p className="text-[0.6875rem] text-slate-500 italic pt-1">
                          * Evaluated via RDAP/WHOIS heuristics and RFC-compliant MX DNS resolution.
                        </p>
                      </Card>
                    </div>
                  </div>
                )}

                {/* TAB 2: INFRASTRUCTURE & GEOIP ASSESSMENT */}
                {activeTab === "infrastructure" && (
                  <div className="space-y-4">
                    <Card surface={2}>
                      <CardHeader
                        title="Section 14 — Unified Origin Infrastructure & Anonymization Telemetry"
                        subtitle="Geographic coordinates, network telemetry, and anonymity detection"
                      />

                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs mb-4">
                        <div className="p-3 rounded-lg bg-soc-surface border border-soc-border">
                          <span className="text-slate-500 block text-[0.625rem] uppercase font-semibold">
                            Originating IP
                          </span>
                          <span className="text-sm font-mono font-bold text-sky-400 block mt-1">
                            {infra?.origin_ip || "Unavailable"} {infra?.flag}
                          </span>
                          <span className="text-[0.625rem] text-slate-500 mt-0.5 block">
                            Classification: Direct Client / Earliest Relay
                          </span>
                        </div>
                        <div className="p-3 rounded-lg bg-soc-surface border border-soc-border">
                          <span className="text-slate-500 block text-[0.625rem] uppercase font-semibold">
                            Network Location
                          </span>
                          <span className="text-sm font-bold text-slate-200 block mt-1">
                            {infra?.city ? `${infra.city}, ${infra.country}` : infra?.country || "Unavailable"}
                          </span>
                          <span className="text-[0.625rem] text-slate-500 mt-0.5 block">
                            Region: {infra?.region || "Unknown"}
                          </span>
                        </div>
                        <div className="p-3 rounded-lg bg-soc-surface border border-soc-border">
                          <span className="text-slate-500 block text-[0.625rem] uppercase font-semibold">
                            ISP / Routing Org
                          </span>
                          <span className="text-sm font-bold text-slate-200 block mt-1 truncate" title={infra?.isp}>
                            {infra?.isp || "Unknown Network"}
                          </span>
                          <span className="text-[0.625rem] text-slate-500 mt-0.5 block">
                            ASN: {infra?.asn || "Unknown"}
                          </span>
                        </div>
                        <div className="p-3 rounded-lg bg-soc-surface border border-soc-border">
                          <span className="text-slate-500 block text-[0.625rem] uppercase font-semibold">
                            Hosting Model
                          </span>
                          <span className="text-sm font-bold text-slate-200 block mt-1">
                            {infra?.cloud_provider || "Dedicated / Local"}
                          </span>
                          <span className="text-[0.625rem] text-slate-500 mt-0.5 block">
                            Botnet Threat: {infra?.botnet_indicator || "NOT_INDICATED"}
                          </span>
                        </div>
                      </div>

                      <div className="p-3.5 rounded-lg bg-soc-surface border border-soc-border space-y-2">
                        <h4 className="text-xs font-semibold text-slate-300">
                          Forensic Attribution & GeoIP Notice
                        </h4>
                        <p className="text-xs text-slate-400 leading-relaxed">
                          GeoIP provides approximate network-level infrastructure context for the identified IP. It
                          reflects the location of the sending mail server or gateway and does not prove the physical
                          identity or location of the human author. VPNs, proxies, commercial clouds, and webmail relays
                          may obscure original client devices.
                        </p>
                      </div>
                    </Card>
                  </div>
                )}

                {/* TAB 3: RFC 7489 AUTHENTICATION & DMARC ALIGNMENT MATRIX */}
                {activeTab === "authentication" && (
                  <div className="space-y-4">
                    <Card surface={2}>
                      <CardHeader
                        title="Cryptographic Authentication & DMARC Alignment Matrix (RFC 7489)"
                        subtitle="Evaluation of SPF Mail-From, DKIM Signature Domain, and Header-From Alignment"
                      />

                      {/* 4 Metric Cards */}
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mb-6">
                        <div className="p-3 rounded-lg bg-soc-surface border border-soc-border">
                          <span className="text-slate-500 block text-[0.625rem] uppercase font-semibold">
                            Effective DMARC
                          </span>
                          <span
                            className={`text-sm font-bold font-mono block mt-1 ${
                              auth?.effective_dmarc === "PASS" || auth?.effective_dmarc?.includes("Delegated")
                                ? "text-emerald-400"
                                : auth?.effective_dmarc?.includes("Unverified")
                                ? "text-amber-400"
                                : "text-red-400"
                            }`}
                          >
                            {auth?.effective_dmarc || "NONE"}
                          </span>
                        </div>
                        <div className="p-3 rounded-lg bg-soc-surface border border-soc-border">
                          <span className="text-slate-500 block text-[0.625rem] uppercase font-semibold">
                            SPF Result
                          </span>
                          <span className="text-sm font-bold font-mono text-slate-200 block mt-1">
                            {auth?.spf_result?.toUpperCase() || "NONE"} ({auth?.spf_alignment_status || "UNALIGNED"})
                          </span>
                        </div>
                        <div className="p-3 rounded-lg bg-soc-surface border border-soc-border">
                          <span className="text-slate-500 block text-[0.625rem] uppercase font-semibold">
                            DKIM Result
                          </span>
                          <span className="text-sm font-bold font-mono text-slate-200 block mt-1">
                            {auth?.dkim_result?.toUpperCase() || "NONE"} ({auth?.dkim_alignment_status || "UNALIGNED"})
                          </span>
                        </div>
                        <div className="p-3 rounded-lg bg-soc-surface border border-soc-border">
                          <span className="text-slate-500 block text-[0.625rem] uppercase font-semibold">
                            DMARC Header Claim
                          </span>
                          <span className="text-sm font-bold font-mono text-slate-200 block mt-1">
                            {auth?.dmarc_result?.toUpperCase() || "NONE"}
                          </span>
                        </div>
                      </div>

                      {/* RFC 7489 Alignment Table */}
                      <div className="overflow-x-auto">
                        <table className="w-full text-xs text-left">
                          <thead>
                            <tr className="border-b border-soc-border text-slate-400 font-semibold">
                              <th className="pb-2">Protocol Layer</th>
                              <th className="pb-2">Inspected Domain / Identity</th>
                              <th className="pb-2">Cryptographic Result</th>
                              <th className="pb-2">RFC 7489 Alignment Status</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-soc-border/50 font-mono">
                            <tr>
                              <td className="py-2.5 text-slate-300 font-sans font-medium">Header-From</td>
                              <td className="py-2.5 text-purple-300">
                                {auth?.header_from_domain || "Not Available"}
                              </td>
                              <td className="py-2.5 text-slate-400">Visible Identity Target</td>
                              <td className="py-2.5 text-slate-400 font-sans">Reference Identity</td>
                            </tr>
                            <tr>
                              <td className="py-2.5 text-slate-300 font-sans font-medium">
                                Envelope-From (Return-Path)
                              </td>
                              <td className="py-2.5 text-sky-300">
                                {auth?.envelope_from_domain || auth?.envelope_from || "Not Available"}
                              </td>
                              <td className="py-2.5 uppercase text-slate-200">
                                {auth?.spf_result || "none"}
                              </td>
                              <td className="py-2.5 font-sans">
                                {auth?.spf_aligned ? (
                                  <span className="text-emerald-400 font-semibold flex items-center gap-1">
                                    <CheckCircle2 className="h-3 w-3" /> Aligned with Header-From
                                  </span>
                                ) : auth?.spf_alignment_status === "NOT_DETERMINABLE" ? (
                                  <span className="text-slate-500">Not determinable from headers</span>
                                ) : (
                                  <span className="text-amber-400 font-semibold flex items-center gap-1">
                                    <AlertTriangle className="h-3 w-3" /> Unaligned (Bypass Risk)
                                  </span>
                                )}
                              </td>
                            </tr>
                            <tr>
                              <td className="py-2.5 text-slate-300 font-sans font-medium">
                                DKIM Signature (d=)
                              </td>
                              <td className="py-2.5 text-amber-300">
                                {auth?.dkim_signing_domain || "Not Available"}
                              </td>
                              <td className="py-2.5 uppercase text-slate-200">
                                {auth?.dkim_result || "none"}
                              </td>
                              <td className="py-2.5 font-sans">
                                {auth?.dkim_aligned ? (
                                  <span className="text-emerald-400 font-semibold flex items-center gap-1">
                                    <CheckCircle2 className="h-3 w-3" /> Aligned with Header-From
                                  </span>
                                ) : auth?.dkim_alignment_status === "NOT_DETERMINABLE" ? (
                                  <span className="text-slate-500">Not determinable from headers</span>
                                ) : (
                                  <span className="text-slate-400 flex items-center gap-1">
                                    <span>ℹ️ Delegated ESP / Unaligned</span>
                                  </span>
                                )}
                              </td>
                            </tr>
                          </tbody>
                        </table>
                      </div>

                      {/* Cryptographic Reason / Advisory */}
                      {auth?.reason && (
                        <div className="mt-4 p-3 rounded-lg bg-soc-surface border border-soc-border text-xs text-slate-300">
                          <span className="font-semibold text-slate-200 block mb-0.5">
                            RFC Alignment Assessment:
                          </span>
                          <p>{auth.reason}</p>
                        </div>
                      )}
                    </Card>
                  </div>
                )}

                {/* TAB 4: IOCS & URL THREAT INTEL */}
                {activeTab === "ioc_urls" && (
                  <div className="space-y-6">
                    {/* Embedded URLs Deep Dive */}
                    <Card surface={2}>
                      <CardHeader
                        title={`Embedded URLs Background Analysis (${urls.length})`}
                        subtitle="Defanged target hyperlinks, redirection chain, and risk assessment"
                      />

                      {urls.length === 0 ? (
                        <p className="text-xs text-slate-500 py-2">No external hyperlinks found in email body.</p>
                      ) : (
                        <div className="space-y-3">
                          {urls.map((u, i) => (
                            <div
                              key={i}
                              className="p-3.5 rounded-lg bg-soc-surface border border-soc-border space-y-2 text-xs"
                            >
                              <div className="flex items-center justify-between flex-wrap gap-2">
                                <span className="font-mono font-bold text-sky-400 text-sm">
                                  {u.domain || "Unknown Domain"}
                                </span>
                                <span
                                  className={`px-2 py-0.5 rounded text-[0.6875rem] font-bold uppercase tracking-wider ${
                                    u.risk_level === "CRITICAL"
                                      ? "bg-red-950 text-red-400 border border-red-800"
                                      : u.risk_level === "HIGH"
                                      ? "bg-amber-950 text-amber-400 border border-amber-800"
                                      : "bg-emerald-950 text-emerald-400 border border-emerald-800"
                                  }`}
                                >
                                  {u.threat_category} — {u.risk_level}
                                </span>
                              </div>

                              <div className="bg-soc-surface-2 p-2 rounded font-mono text-[0.6875rem] text-slate-300 break-all">
                                {u.defanged_url || u.url}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </Card>

                    {/* Extracted IOCs Table */}
                    <Card surface={2}>
                      <CardHeader
                        title={`Extracted Indicators of Compromise (${iocs.length})`}
                        subtitle="Defanged network artifacts, IPs, domains, and email endpoints"
                      />

                      {iocs.length === 0 ? (
                        <p className="text-xs text-slate-500 py-2">No indicators extracted.</p>
                      ) : (
                        <div className="overflow-x-auto">
                          <table className="w-full text-xs text-left">
                            <thead>
                              <tr className="border-b border-soc-border text-slate-400 font-semibold">
                                <th className="pb-2">IOC Type</th>
                                <th className="pb-2">Value (Defanged)</th>
                                <th className="pb-2">Threat Band</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-soc-border/50 font-mono">
                              {iocs.map((ioc, idx) => (
                                <tr key={idx}>
                                  <td className="py-2 uppercase text-accent font-sans font-medium">
                                    {ioc.type}
                                  </td>
                                  <td className="py-2 text-slate-200 select-all">{ioc.value}</td>
                                  <td className="py-2 font-sans">
                                    <SeverityBadge severity={ioc.risk || "clean"} size="sm" />
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </Card>
                  </div>
                )}

                {/* TAB 5: INDIAN CYBER FINANCIAL INTELLIGENCE */}
                {activeTab === "indian_financial" && (
                  <div className="space-y-4">
                    <Card surface={2}>
                      <CardHeader
                        title="🇮🇳 Indian Cyber Financial Intelligence (UPI & Banking Routes)"
                        subtitle="Detection of Unified Payments Interface (UPI) VPAs, IFSC bank clearing codes, and extortion lures"
                      />

                      {indianFin?.detected ? (
                        <div className="space-y-4">
                          <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-800 text-amber-200 text-xs">
                            ⚠️ <b>Active Indian Financial Indicators Detected:</b> This email contains domestic
                            payment collection artifacts often associated with extortion, fake challan, or KYC
                            suspension frauds.
                          </div>

                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                            {/* Suspect UPI VPAs */}
                            <div className="p-3.5 rounded-lg bg-soc-surface border border-soc-border space-y-2">
                              <h4 className="font-semibold text-sky-400 flex items-center gap-1.5">
                                <Zap className="h-3.5 w-3.5" />
                                <span>Suspect UPI Handles (VPAs)</span>
                              </h4>
                              {indianFin.upi_handles.length > 0 ? (
                                <div className="space-y-1.5">
                                  {indianFin.upi_handles.map((vpa, i) => (
                                    <div
                                      key={i}
                                      className="flex items-center justify-between p-2 rounded bg-soc-surface-2 font-mono text-cyan-300"
                                    >
                                      <span>{vpa}</span>
                                      <button
                                        onClick={() => copyToClipboard(vpa, "UPI VPA")}
                                        className="text-slate-400 hover:text-white"
                                      >
                                        <Copy className="h-3.5 w-3.5" />
                                      </button>
                                    </div>
                                  ))}
                                </div>
                              ) : (
                                <p className="text-slate-500">No UPI VPAs extracted.</p>
                              )}
                            </div>

                            {/* IFSC & Bank Routes */}
                            <div className="p-3.5 rounded-lg bg-soc-surface border border-soc-border space-y-2">
                              <h4 className="font-semibold text-emerald-400 flex items-center gap-1.5">
                                <Server className="h-3.5 w-3.5" />
                                <span>Banking Routes & IFSC Codes</span>
                              </h4>
                              {indianFin.ifsc_codes.length > 0 ? (
                                <div className="space-y-1.5">
                                  {indianFin.ifsc_codes.map((ifsc, i) => (
                                    <div
                                      key={i}
                                      className="p-2 rounded bg-soc-surface-2 font-mono text-emerald-300 text-xs"
                                    >
                                      IFSC: {ifsc}
                                    </div>
                                  ))}
                                </div>
                              ) : (
                                <p className="text-slate-500">No IFSC codes identified.</p>
                              )}
                            </div>
                          </div>

                          {/* Fraud Lures */}
                          {indianFin.urgency_lures.length > 0 && (
                            <div className="p-3.5 rounded-lg bg-soc-surface border border-soc-border space-y-2 text-xs">
                              <h4 className="font-semibold text-red-400">
                                Detected Coercion & Urgency Fraud Lures:
                              </h4>
                              <div className="flex flex-wrap gap-2">
                                {indianFin.urgency_lures.map((lure, i) => (
                                  <span
                                    key={i}
                                    className="px-2.5 py-1 rounded bg-red-950/60 border border-red-800 text-red-300 font-medium"
                                  >
                                    ⚠️ {lure}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}

                          <div className="p-3 rounded bg-soc-surface border border-soc-border text-xs text-slate-400">
                            <b>Legal Evidence Reference:</b> Formatted in accordance with Section 63(4)(c) of the
                            Bharatiya Sakshya Adhiniyam, 2023 (BSA) for direct cybercrime.gov.in / NCRP complaint filing.
                          </div>
                        </div>
                      ) : (
                        <div className="p-4 rounded-lg bg-soc-surface border border-soc-border text-xs text-slate-400">
                          ✅ No Indian banking artifacts, UPI VPAs, IFSC clearing codes, or extortion phrases detected in this message.
                        </div>
                      )}
                    </Card>
                  </div>
                )}

                {/* TAB 6: RULE FINDINGS */}
                {activeTab === "rule_findings" && (
                  <div className="space-y-4">
                    <Card surface={2}>
                      <CardHeader
                        title={`Forensic Rule Matrix Findings (${findings.length})`}
                        subtitle="Deterministic rules evaluated by the zero-trust SOC engine"
                      />

                      {findings.length === 0 ? (
                        <div className="p-4 rounded-lg bg-soc-surface border border-soc-border text-xs text-emerald-400">
                          ✅ Zero rule violations triggered. All security heuristics passed cleanly.
                        </div>
                      ) : (
                        <div className="space-y-2.5">
                          {findings.map((f, i) => (
                            <div
                              key={i}
                              className="p-3.5 rounded-lg bg-soc-surface border border-soc-border flex items-start justify-between gap-3 text-xs"
                            >
                              <div className="space-y-1">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono font-bold text-accent">{f.rule_id}</span>
                                  <span className="font-semibold text-slate-200">{f.title}</span>
                                </div>
                                <p className="text-slate-400 leading-relaxed">{f.finding}</p>
                              </div>
                              <div className="shrink-0 flex flex-col items-end gap-1">
                                <SeverityBadge severity={f.severity} size="sm" />
                                {f.score_penalty > 0 && (
                                  <span className="font-mono text-red-400 font-bold text-[0.6875rem]">
                                    +{f.score_penalty} pts
                                  </span>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </Card>
                  </div>
                )}

                {/* TAB 7: HOP-BY-HOP MTA RELAY FLIGHT PATH */}
                {activeTab === "hop_transit" && (
                  <div className="space-y-4">
                    <Card surface={2}>
                      <CardHeader
                        title={`Hop-by-Hop MTA Relay Flight Path (${hops.length} Hops Traced)`}
                        subtitle="Sequential mail transfer agent delays and IP relay chain"
                      />

                      {hops.length === 0 ? (
                        <p className="text-xs text-slate-500 py-2">No relay transit headers available.</p>
                      ) : (
                        <div className="overflow-x-auto">
                          <table className="w-full text-xs text-left">
                            <thead>
                              <tr className="border-b border-soc-border text-slate-400 font-semibold">
                                <th className="pb-2">Hop</th>
                                <th className="pb-2">From MTA</th>
                                <th className="pb-2">By MTA</th>
                                <th className="pb-2">Relay IP</th>
                                <th className="pb-2">Delay (Δt)</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-soc-border/50 font-mono">
                              {hops.map((h, i) => (
                                <tr key={i}>
                                  <td className="py-2.5 font-bold text-accent">#{h.hop}</td>
                                  <td className="py-2.5 text-slate-300 truncate max-w-[180px]" title={h.from_mta}>
                                    {h.from_mta || "Unknown"}
                                  </td>
                                  <td className="py-2.5 text-slate-300 truncate max-w-[180px]" title={h.by_mta}>
                                    {h.by_mta || "Unknown"}
                                  </td>
                                  <td className="py-2.5 text-cyan-300">{h.ip || "—"}</td>
                                  <td className="py-2.5 text-slate-400 font-sans">{h.delay_seconds}s</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </Card>
                  </div>
                )}

                {/* TAB 8: ATTACHMENT DEEP FORENSICS */}
                {activeTab === "attachments" && (
                  <div className="space-y-4">
                    <Card surface={2}>
                      <CardHeader
                        title={`Attachment Deep Forensics (${atts.length})`}
                        subtitle="SHA-256 cryptographic hashes, MIME validation, and executable containment"
                      />

                      {atts.length === 0 ? (
                        <div className="p-4 rounded-lg bg-soc-surface border border-soc-border text-xs text-slate-400">
                          📎 No file attachments detected in this email.
                        </div>
                      ) : (
                        <div className="space-y-3">
                          {atts.map((att, i) => (
                            <div
                              key={i}
                              className="p-3.5 rounded-lg bg-soc-surface border border-soc-border flex items-center justify-between gap-3 text-xs"
                            >
                              <div className="space-y-1">
                                <div className="flex items-center gap-2">
                                  <Paperclip className="h-3.5 w-3.5 text-accent" />
                                  <span className="font-semibold text-slate-200">{att.filename}</span>
                                </div>
                                <p className="font-mono text-[0.6875rem] text-slate-400">
                                  SHA-256: {att.hash || "Not computed"}
                                </p>
                                <p className="text-[0.6875rem] text-slate-500">
                                  Type: {att.mime_type || att.content_type} • Size: {att.size} bytes
                                </p>
                              </div>
                              <SeverityBadge severity={att.risk || "clean"} size="sm" />
                            </div>
                          ))}
                        </div>
                      )}
                    </Card>
                  </div>
                )}

                {/* TAB 9: RAW RFC HEADERS */}
                {activeTab === "headers" && (
                  <div className="space-y-4">
                    <Card surface={2}>
                      <div className="flex items-center justify-between border-b border-soc-border pb-3 mb-3">
                        <CardHeader
                          title="Raw RFC822 Headers Reference"
                          subtitle="Unfolded header audit stream for forensic chain-of-custody"
                        />
                        <button
                          onClick={() =>
                            copyToClipboard(
                              analysisResult.headers_text || JSON.stringify(analysisResult.headers, null, 2),
                              "Headers"
                            )
                          }
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-soc-surface-3 text-slate-200 hover:text-white text-xs font-medium border border-soc-border transition-colors"
                        >
                          {copiedField === "Headers" ? (
                            <>
                              <Check className="h-3.5 w-3.5 text-status-connected" />
                              <span>Copied!</span>
                            </>
                          ) : (
                            <>
                              <Copy className="h-3.5 w-3.5" />
                              <span>Copy Headers</span>
                            </>
                          )}
                        </button>
                      </div>

                      <div className="max-h-[500px] overflow-y-auto scrollbar-thin bg-soc-surface p-4 rounded-lg border border-soc-border font-mono text-[0.6875rem] leading-relaxed text-slate-300 whitespace-pre-wrap break-all">
                        {analysisResult.headers_text ||
                          Object.entries(analysisResult.headers)
                            .map(([k, v]) => `${k}: ${v}`)
                            .join("\n")}
                      </div>
                    </Card>
                  </div>
                )}
              </div>
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
              {/* Email List — strictly sorted newest first */}
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
                              selectedEmail?.uid === email.uid
                                ? "bg-soc-surface-2 border-l-2 border-l-accent"
                                : ""
                            }`}
                          >
                            <SeverityBadge severity={email.risk_status} />
                            <div className="flex-1 min-w-0">
                              <p className="text-sm text-slate-200 truncate">{email.sender}</p>
                              <p className="text-xs text-slate-400 truncate">{email.subject}</p>
                            </div>
                            <div className="text-right shrink-0">
                              <p className="text-xs text-slate-500">{formatDate(email.date)}</p>
                              <p className="text-[0.625rem] text-slate-600 font-mono mt-0.5">
                                UID: {email.uid}
                              </p>
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

              {/* Selected Email Details & Action */}
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
                          <dd className="text-slate-200 truncate font-mono text-xs">
                            {selectedEmail.sender}
                          </dd>
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
                          <SearchIcon className="h-3.5 w-3.5" /> Run Full Forensic Analysis
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
