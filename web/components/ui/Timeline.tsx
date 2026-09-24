// web/components/ui/Timeline.tsx
import type { TimelineEvent } from '@/lib/types/soc';
import { formatDate } from '@/lib/constants';
import { Circle } from 'lucide-react';

export function Timeline({ events }: { events: TimelineEvent[] }) {
  if (!events.length) {
    return <p className="text-xs text-slate-500 py-4 text-center">No timeline events recorded.</p>;
  }
  return (
    <div className="space-y-0">
      {events.map((event, i) => (
        <div key={i} className="flex gap-3 pb-4 last:pb-0">
          <div className="flex flex-col items-center">
            <Circle className="h-2 w-2 fill-current text-accent mt-1.5 shrink-0" />
            {i < events.length - 1 && <div className="w-px flex-1 bg-soc-border mt-1" />}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm text-slate-200">{event.event}</p>
            {event.detail && <p className="text-xs text-slate-400 mt-0.5">{event.detail}</p>}
            <p className="text-xs text-slate-500 mt-1 font-mono">{formatDate(event.timestamp)}</p>
          </div>
        </div>
      ))}
    </div>
  );
}
