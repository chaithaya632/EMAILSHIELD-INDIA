// web/components/ui/EvidenceBlock.tsx
import type { EvidenceItem } from '@/lib/types/soc';
import { formatDate } from '@/lib/constants';
import { FileText, Fingerprint, Shield } from 'lucide-react';

const typeIcons: Record<string, typeof FileText> = {
  file: FileText,
  hash: Fingerprint,
  auth: Shield,
};

export function EvidenceBlock({ items }: { items: EvidenceItem[] }) {
  if (!items.length) {
    return <p className="text-xs text-slate-500 py-4 text-center">No evidence collected.</p>;
  }
  return (
    <div className="space-y-2">
      {items.map((item) => {
        const Icon = typeIcons[item.type] ?? FileText;
        return (
          <div
            key={item.id}
            className="flex items-start gap-3 p-3 bg-soc-surface-2 border border-soc-border rounded-md"
          >
            <Icon className="h-4 w-4 text-slate-500 mt-0.5 shrink-0" />
            <div className="flex-1 min-w-0">
              <p className="text-sm text-slate-200">{item.description}</p>
              <div className="flex items-center gap-3 mt-1 flex-wrap">
                <span className="text-xs text-slate-500 font-mono">{item.type}</span>
                {item.hash && (
                  <span className="text-xs text-slate-500 font-mono truncate max-w-xs">
                    {item.hash}
                  </span>
                )}
                {item.collected_at && (
                  <span className="text-xs text-slate-500">{formatDate(item.collected_at)}</span>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
