// web/lib/constants.ts
import type { Severity, AnalysisState, WorkerStatus } from '@/lib/types/soc';

export const SEVERITY_LABELS: Record<Severity, string> = {
  clean: 'CLEAN',
  suspicious: 'SUSPICIOUS',
  high: 'HIGH',
  critical: 'CRITICAL',
  not_analyzed: 'NOT ANALYZED',
};

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'suspicious', 'clean', 'not_analyzed'];

export const SEVERITY_STYLES: Record<Severity, string> = {
  clean: 'bg-severity-clean-bg text-severity-clean border-severity-clean-border',
  suspicious: 'bg-severity-suspicious-bg text-severity-suspicious border-severity-suspicious-border',
  high: 'bg-severity-high-bg text-severity-high border-severity-high-border',
  critical: 'bg-severity-critical-bg text-severity-critical border-severity-critical-border',
  not_analyzed: 'bg-soc-surface-3 text-slate-400 border-soc-border-light',
};

export const SEVERITY_DOT: Record<Severity, string> = {
  clean: 'bg-severity-clean',
  suspicious: 'bg-severity-suspicious',
  high: 'bg-severity-high',
  critical: 'bg-severity-critical',
  not_analyzed: 'bg-slate-500',
};

export const ANALYSIS_STATE_LABELS: Record<AnalysisState, string> = {
  pending: 'Pending',
  analyzing: 'Analyzing',
  completed: 'Completed',
  failed: 'Failed',
  not_analyzed: 'Not Analyzed',
};

export const WORKER_STATUS_LABELS: Record<WorkerStatus, string> = {
  connected: 'Connected',
  monitoring: 'Monitoring',
  processing: 'Processing',
  error: 'Error',
  offline: 'Offline',
};

export const WORKER_STATUS_STYLES: Record<WorkerStatus, string> = {
  connected: 'text-status-connected',
  monitoring: 'text-status-monitoring',
  processing: 'text-status-processing',
  error: 'text-status-error',
  offline: 'text-status-offline',
};

export const WORKER_STATUS_DOT: Record<WorkerStatus, string> = {
  connected: 'bg-status-connected',
  monitoring: 'bg-status-monitoring',
  processing: 'bg-status-processing',
  error: 'bg-status-error',
  offline: 'bg-status-offline',
};

export const FETCH_LIMITS = [50, 100, 200] as const;

export function maskValue(value: string): string {
  if (!value) return '—';
  if (value.includes('@')) {
    const [name, domain] = value.split('@');
    return `${name[0]}******@${domain}`;
  }
  // phone-like
  const digits = value.replace(/\D/g, '');
  if (digits.length >= 4) {
    return `+${digits.length > 10 ? digits.slice(0, -10) : ''}******${digits.slice(-4)}`;
  }
  return '******';
}

export function formatDate(dateStr: string): string {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return dateStr;
  return d.toLocaleString('en-IN', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true,
    timeZone: 'Asia/Kolkata',
  });
}

export function formatRelative(dateStr: string): string {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return dateStr;
  const diff = Date.now() - d.getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return formatDate(dateStr);
}

export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}
