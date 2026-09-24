// web/components/ui/Card.tsx
import { type HTMLAttributes, forwardRef } from 'react';

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  surface?: 1 | 2;
  noPadding?: boolean;
}

export const Card = forwardRef<HTMLDivElement, CardProps>(
  ({ surface = 1, noPadding, className, children, ...props }, ref) => (
    <div
      ref={ref}
      className={`rounded-[10px] border border-soc-border ${surface === 1 ? 'bg-soc-surface' : 'bg-soc-surface-2'} ${noPadding ? '' : 'p-4'} transition-colors duration-150 ${className ?? ''}`}
      {...props}
    >
      {children}
    </div>
  )
);

Card.displayName = 'Card';

interface CardHeaderProps extends HTMLAttributes<HTMLDivElement> {
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
}

export function CardHeader({ title, subtitle, action, className }: CardHeaderProps) {
  return (
    <div className={`flex items-start justify-between mb-4 ${className ?? ''}`}>
      <div>
        <h3 className="text-sm font-semibold text-slate-100">{title}</h3>
        {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}
