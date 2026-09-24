// web/components/ui/Badge.tsx
import type { Severity, WorkerStatus, AnalysisState } from '@/lib/types/soc';
import {
  SEVERITY_LABELS,
  SEVERITY_STYLES,
  SEVERITY_DOT,
  WORKER_STATUS_LABELS,
  WORKER_STATUS_STYLES,
  WORKER_STATUS_DOT,
  ANALYSIS_STATE_LABELS,
} from '@/lib/constants';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md';
}

export function SeverityBadge({ severity, size = 'sm' }: SeverityBadgeProps) {
  const sizeCls = size === 'sm' ? 'text-[0.6875rem] px-2 py-0.5' : 'text-xs px-2.5 py-1';
  return (
    <span
      data-testid={`badge-severity-${severity}`}
      className={`inline-flex items-center gap-1.5 rounded border font-semibold uppercase tracking-[0.08em] ${SEVERITY_STYLES[severity]} ${sizeCls}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${SEVERITY_DOT[severity]}`} />
      {SEVERITY_LABELS[severity]}
    </span>
  );
}

interface StatusBadgeProps {
  status: WorkerStatus;
  size?: 'sm' | 'md';
}

export function StatusBadge({ status, size = 'sm' }: StatusBadgeProps) {
  const sizeCls = size === 'sm' ? 'text-[0.6875rem] px-2 py-0.5' : 'text-xs px-2.5 py-1';
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border border-soc-border-light bg-soc-surface-2 font-medium ${WORKER_STATUS_STYLES[status]} ${sizeCls}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${WORKER_STATUS_DOT[status]} ${status === 'processing' ? 'animate-pulse-soft' : ''}`} />
      {WORKER_STATUS_LABELS[status]}
    </span>
  );
}

interface AnalysisStateBadgeProps {
  state: AnalysisState;
}

export function AnalysisStateBadge({ state }: AnalysisStateBadgeProps) {
  const styles: Record<AnalysisState, string> = {
    pending: 'text-status-processing',
    analyzing: 'text-status-processing',
    completed: 'text-status-connected',
    failed: 'text-status-error',
    not_analyzed: 'text-slate-500',
  };
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-medium ${styles[state]}`}>
      {ANALYSIS_STATE_LABELS[state]}
    </span>
  );
}
