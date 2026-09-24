// web/components/ui/States.tsx
import { type ReactNode } from 'react';
import { AlertCircle, Inbox, WifiOff, Lock, FileQuestion, UploadCloud } from 'lucide-react';
import { Button } from './Button';

interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  message?: string;
  action?: { label: string; onClick: () => void };
}

export function EmptyState({ icon, title, message, action }: EmptyStateProps) {
  return (
    <div data-testid="state-empty" className="flex flex-col items-center justify-center py-12 px-4 text-center animate-fade-in">
      <div className="text-slate-600 mb-3">
        {icon ?? <Inbox className="h-10 w-10" />}
      </div>
      <p className="text-sm font-medium text-slate-300">{title}</p>
      {message && <p className="text-xs text-slate-500 mt-1 max-w-sm">{message}</p>}
      {action && (
        <Button variant="secondary" size="sm" onClick={action.onClick} className="mt-4">
          {action.label}
        </Button>
      )}
    </div>
  );
}

interface ErrorStateProps {
  type?: 'auth' | 'denied' | 'unavailable' | 'connection' | 'invalid' | 'upload' | 'unexpected';
  title?: string;
  message?: string;
  onRetry?: () => void;
}

const errorConfig: Record<string, { icon: ReactNode; title: string; message: string }> = {
  auth: { icon: <Lock className="h-10 w-10" />, title: 'Authentication Required', message: 'You must be signed in to access this resource.' },
  denied: { icon: <Lock className="h-10 w-10" />, title: 'Access Denied', message: 'You do not have permission to access this resource.' },
  unavailable: { icon: <FileQuestion className="h-10 w-10" />, title: 'Data Unavailable', message: 'The requested data could not be loaded.' },
  connection: { icon: <WifiOff className="h-10 w-10" />, title: 'Connection Error', message: 'Unable to reach the server. Please check your connection.' },
  invalid: { icon: <AlertCircle className="h-10 w-10" />, title: 'Invalid Email', message: 'The provided email could not be parsed or analyzed.' },
  upload: { icon: <UploadCloud className="h-10 w-10" />, title: 'Upload Too Large', message: 'The uploaded file exceeds the maximum allowed size.' },
  unexpected: { icon: <AlertCircle className="h-10 w-10" />, title: 'Unexpected Error', message: 'An unexpected error occurred. Please try again.' },
};

export function ErrorState({ type = 'unexpected', title, message, onRetry }: ErrorStateProps) {
  const config = errorConfig[type];
  return (
    <div data-testid="state-error" className="flex flex-col items-center justify-center py-12 px-4 text-center animate-fade-in">
      <div className="text-severity-critical mb-3">{config.icon}</div>
      <p className="text-sm font-medium text-slate-200">{title ?? config.title}</p>
      <p className="text-xs text-slate-500 mt-1 max-w-sm">{message ?? config.message}</p>
      {onRetry && (
        <Button variant="secondary" size="sm" onClick={onRetry} className="mt-4">
          Retry
        </Button>
      )}
    </div>
  );
}
