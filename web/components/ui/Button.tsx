// web/components/ui/Button.tsx
import { type ButtonHTMLAttributes, forwardRef } from 'react';

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'success';
type Size = 'sm' | 'md' | 'lg';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
}

const variantClasses: Record<Variant, string> = {
  primary: 'bg-accent hover:bg-accent-hover text-[#06141a] border-transparent shadow-[0_5px_14px_rgba(43,183,169,.12)]',
  secondary: 'bg-soc-surface-2 hover:bg-soc-surface-3 text-slate-200 border-soc-border-light',
  ghost: 'bg-transparent hover:bg-soc-surface-2 text-slate-300 border-transparent',
  danger: 'bg-severity-critical-bg hover:bg-severity-critical text-white border-severity-critical-border',
  success: 'bg-severity-clean-bg hover:bg-severity-clean text-white border-severity-clean-border',
};

const sizeClasses: Record<Size, string> = {
  sm: 'text-xs px-2.5 py-1.5 gap-1.5',
  md: 'text-sm px-3.5 py-2 gap-2',
  lg: 'text-base px-5 py-2.5 gap-2',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'secondary', size = 'md', loading, className, children, disabled, ...props }, ref) => (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={`inline-flex items-center justify-center rounded-md border font-medium transition-[background-color,color,border-color,transform] duration-150 hover:-translate-y-px focus-visible:ring-2 focus-visible:ring-accent/40 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:translate-y-0 ${variantClasses[variant]} ${sizeClasses[size]} ${className ?? ''}`}
      {...props}
    >
      {loading && (
        <span className="h-3.5 w-3.5 border-2 border-current border-t-transparent rounded-full animate-spin" />
      )}
      {children}
    </button>
  )
);

Button.displayName = 'Button';
