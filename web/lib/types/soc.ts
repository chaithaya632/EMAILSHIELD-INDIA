// web/lib/types/soc.ts
// Shared types for EMAILSHIELD INDIA SOC platform

export type Severity = 'clean' | 'suspicious' | 'high' | 'critical' | 'not_analyzed';

export type WorkerStatus = 'connected' | 'monitoring' | 'processing' | 'error' | 'offline';

export type AnalysisState = 'pending' | 'analyzing' | 'completed' | 'failed' | 'not_analyzed';

export type CaseStatus = 'open' | 'in_progress' | 'closed' | 'escalated';

export type PageKey =
  | 'dashboard'
  | 'analyze'
  | 'live-mail'
  | 'investigations'
  | 'intel'
  | 'attack-graph'
  | 'reports'
  | 'alerts'
  | 'settings'
  | 'diagnostics';

export interface EmailSummary {
  uid: string;
  sender: string;
  subject: string;
  date: string;
  risk_status: Severity;
  analysis_state: AnalysisState;
  message_id?: string;
}

export interface EmailDetail {
  uid: string;
  sender: string;
  recipient: string;
  subject: string;
  date: string;
  body_preview: string;
  headers: Record<string, string>;
  authentication: {
    spf: 'pass' | 'fail' | 'neutral' | 'none';
    dkim: 'pass' | 'fail' | 'neutral' | 'none';
    dmarc: 'pass' | 'fail' | 'neutral' | 'none';
  };
  urls: string[];
  indicators: Indicator[];
  attachments: Attachment[];
  risk_score: number;
  risk_status: Severity;
  analysis_state: AnalysisState;
  timeline: TimelineEvent[];
  evidence: EvidenceItem[];

  // Enhanced Forensic Capabilities
  sha256?: string;
  case_id?: string;
  sender_domain?: string;
  ai_reasoning?: string;
  plain_language_summary?: string;
  headers_text?: string;
  auth_alignment?: {
    header_from_domain: string;
    envelope_from: string;
    envelope_from_domain: string;
    dkim_signing_domain: string;
    spf_result: string;
    dkim_result: string;
    dmarc_result: string;
    spf_aligned: boolean;
    dkim_aligned: boolean;
    spf_alignment_status: string;
    dkim_alignment_status: string;
    effective_dmarc: string;
    threat_detected: boolean;
    reason: string;
  };
  infrastructure_intel?: {
    origin_ip: string;
    flag: string;
    country: string;
    region: string;
    city: string;
    asn: string;
    isp: string;
    is_identified: boolean;
    cloud_provider: string;
    vpn_indicator: string;
    tor_indicator: string;
    open_relay_indicator: string;
    botnet_indicator: string;
    threat_feed_match: string;
  };
  domain_reputation?: {
    domain: string;
    registrar: string;
    creation_date: string;
    domain_age_days: number | null;
    is_newly_registered: boolean;
  };
  indian_financial?: {
    detected: boolean;
    upi_handles: string[];
    ifsc_codes: string[];
    urgency_lures: string[];
    fraud_keywords: string[];
  };
  findings?: Array<{
    rule_id: string;
    title: string;
    finding: string;
    severity: Severity;
    score_penalty: number;
  }>;
  hop_transit?: Array<{
    hop: number;
    from_mta: string;
    by_mta: string;
    ip: string;
    timestamp: string;
    delay_seconds: number;
  }>;
  url_threats?: Array<{
    url: string;
    defanged_url: string;
    domain: string;
    threat_category: string;
    risk_level: string;
  }>;
}

export interface Indicator {
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email';
  value: string;
  reputation?: string;
  risk?: Severity;
}

export interface Attachment {
  filename: string;
  content_type: string;
  mime_type?: string;
  size: number;
  hash?: string;
  risk?: Severity;
}

export interface TimelineEvent {
  timestamp: string;
  event: string;
  detail?: string;
}

export interface EvidenceItem {
  id: string;
  type: string;
  description: string;
  hash?: string;
  collected_at?: string;
}

export interface DashboardData {
  total_cases: number;
  high_critical: number;
  suspicious: number;
  clean: number;
  threat_distribution: Record<string, number>;
  threat_timeline: { date: string; count: number }[];
  investigation_queue: { id: string; subject: string; severity: Severity; created: string }[];
  recent_cases: CaseSummary[];
}

export interface CaseSummary {
  id: string;
  severity: Severity;
  subject: string;
  created: string;
  status: CaseStatus;
  assigned_to?: string;
}

export interface CaseDetail {
  id: string;
  severity: Severity;
  subject: string;
  created: string;
  status: CaseStatus;
  assigned_to?: string;
  overview: string;
  evidence: EvidenceItem[];
  timeline: TimelineEvent[];
  indicators: Indicator[];
  related_emails: EmailSummary[];
  attack_relationships: { node: string; type: string; risk: Severity }[];
  reports: ReportSummary[];
}

export type MailboxState = 'NO_MAILBOX' | 'CONNECTED' | 'ACTIVE' | 'WORKER_ERROR';

export interface MailboxInfo {
  id?: string;
  email_address: string;
  provider: string;
  is_active: boolean;
  created_at?: string;
}

export interface LiveMailTelemetry {
  connected?: boolean;
  state?: MailboxState;
  mailbox?: MailboxInfo | null;
  emails_arrived: number;
  emails_analysed: number;
  threats_detected: number;
  high_critical: number;
  duplicates: number;
  processing_errors: number;
  last_uid: number;
  last_poll: string;
  worker_status: WorkerStatus;
}

export interface IntelResult {
  indicator: string;
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email';
  reputation?: string;
  geoip?: { country: string; city: string; lat: number; lon: number; isp: string };
  rdap?: { registrar: string; created: string; expires: string; status: string[] };
  dns?: { type: string; value: string }[];
  authentication?: { spf: string; dkim: string; dmarc: string };
  risk: Severity;
  evidence?: EvidenceItem[];
  read_only: boolean;
}

export interface ReportSummary {
  id: string;
  type: 'PDF' | 'JSON' | 'CSV' | 'NCRP' | 'BSA';
  status: 'available' | 'generating' | 'error';
  created: string;
  investigation_id: string;
}

export interface AlertConfig {
  provider: 'telegram' | 'whatsapp';
  connected: boolean;
  destination?: string;
  status: WorkerStatus;
}

export interface SettingsData {
  profile: { name: string; email: string; role: string };
  live_mail: {
    mailbox_configured: boolean;
    mailbox_address?: string;
    worker_enabled: boolean;
    last_checkpoint: number;
    fetch_limit: number;
  };
  alert_config: AlertConfig[];
}

export interface DiagnosticsData {
  worker_status: WorkerStatus;
  last_poll: string;
  last_uid: number;
  api_health: 'healthy' | 'degraded' | 'down';
  supabase_health: 'healthy' | 'degraded' | 'down';
  config_status: 'configured' | 'partial' | 'missing';
  auth_status: 'authenticated' | 'unauthenticated' | 'expired';
}

export interface GraphNode {
  id: string;
  type: 'email' | 'ip' | 'domain' | 'url' | 'case';
  value: string;
  risk: Severity;
  x?: number;
  y?: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: string;
}

export interface AttackGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}
