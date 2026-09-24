// web/components/live-mail/ConnectMailboxModal.tsx
"use client";

import { useState } from "react";
import { Modal } from "@/components/ui/Modal";
import { connectMailbox } from "@/lib/api";
import {
  Mail,
  Lock,
  Server,
  ShieldCheck,
  AlertCircle,
  CheckCircle2,
  Loader2,
  Eye,
  EyeOff,
  ExternalLink,
} from "lucide-react";

interface ConnectMailboxModalProps {
  open: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export function ConnectMailboxModal({ open, onClose, onSuccess }: ConnectMailboxModalProps) {
  const [email, setEmail] = useState("");
  const [appPassword, setAppPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [statusStep, setStatusStep] = useState<string>("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const resetForm = () => {
    setEmail("");
    setAppPassword("");
    setLoading(false);
    setStatusStep("");
    setErrorMessage(null);
    setSuccessMessage(null);
  };

  const handleClose = () => {
    if (loading) return;
    resetForm();
    onClose();
  };

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !appPassword) return;

    setLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);
    setStatusStep("Connecting to imap.gmail.com:993 and validating TLS...");

    try {
      setStatusStep("Authenticating credentials & selecting INBOX...");
      const res = await connectMailbox(email, appPassword, false);
      if (res?.success) {
        setStatusStep("Mailbox connected and monitoring active!");
        setSuccessMessage(res.message || "Mailbox connected successfully.");
        setTimeout(() => {
          resetForm();
          onSuccess();
          onClose();
        }, 1200);
      } else {
        setErrorMessage(res?.message || "Failed to connect mailbox.");
      }
    } catch (err: any) {
      setErrorMessage(err?.message || "Failed to establish IMAP connection to Gmail.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title="Connect Gmail Mailbox"
      size="md"
      footer={
        <div className="flex items-center justify-between w-full">
          <span className="text-xs text-slate-500 flex items-center gap-1 font-mono">
            <Lock className="h-3 w-3 text-status-connected" /> Worker RSA-OAEP Encrypted
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleClose}
              disabled={loading}
              className="text-xs px-3.5 py-2 rounded-md text-slate-300 hover:bg-soc-surface-2 transition-colors disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              form="connect-mailbox-form"
              disabled={loading || !email.trim() || !appPassword.trim()}
              className="flex items-center gap-1.5 text-xs px-4 py-2 rounded-md font-medium text-white bg-accent hover:bg-accent-hover transition-colors disabled:opacity-50 shadow-md shadow-accent/20"
            >
              {loading ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  <span>Connecting & Testing...</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="h-3.5 w-3.5" />
                  <span>Connect & Test</span>
                </>
              )}
            </button>
          </div>
        </div>
      }
    >
      <form id="connect-mailbox-form" onSubmit={handleConnect} className="space-y-4">
        {/* Connection Spec Summary */}
        <div className="grid grid-cols-2 gap-2 text-xs p-3 bg-soc-surface-2 border border-soc-border rounded-md">
          <div>
            <span className="text-slate-400">Provider:</span>{" "}
            <span className="text-slate-200 font-medium">Gmail</span>
          </div>
          <div>
            <span className="text-slate-400">Host:</span>{" "}
            <span className="text-slate-200 font-mono">imap.gmail.com:993</span>
          </div>
          <div>
            <span className="text-slate-400">TLS:</span>{" "}
            <span className="text-status-connected font-medium">Required (TLSv1.2+)</span>
          </div>
          <div>
            <span className="text-slate-400">Auth Method:</span>{" "}
            <span className="text-slate-200 font-medium">Google App Password</span>
          </div>
        </div>

        {/* Email Address */}
        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1.5">
            Gmail Address
          </label>
          <div className="relative">
            <Mail className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="operator@gmail.com"
              disabled={loading}
              className="w-full bg-soc-surface-2 border border-soc-border rounded-md pl-9 pr-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-accent"
            />
          </div>
        </div>

        {/* App Password */}
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label className="block text-xs font-medium text-slate-300">
              Google App Password (16 characters)
            </label>
            <a
              href="https://myaccount.google.com/apppasswords"
              target="_blank"
              rel="noreferrer"
              className="text-[11px] text-accent hover:underline flex items-center gap-1"
            >
              Generate App Password <ExternalLink className="h-2.5 w-2.5" />
            </a>
          </div>
          <div className="relative">
            <Lock className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
            <input
              type={showPassword ? "text" : "password"}
              required
              value={appPassword}
              onChange={(e) => setAppPassword(e.target.value)}
              placeholder="abcd efgh ijkl mnop"
              disabled={loading}
              autoComplete="off"
              className="w-full bg-soc-surface-2 border border-soc-border rounded-md pl-9 pr-10 py-2 text-sm text-slate-100 placeholder:text-slate-500 font-mono focus:outline-none focus:border-accent"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-2.5 text-slate-400 hover:text-slate-200"
              tabIndex={-1}
            >
              {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
          <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed">
            Standard Google account passwords are not accepted. Use a 16-character App Password generated under Google Account &gt; Security &gt; 2-Step Verification &gt; App passwords.
          </p>
        </div>

        {/* Status / Loading Progress */}
        {loading && (
          <div className="flex items-center gap-2.5 p-3 rounded-md bg-accent/10 border border-accent/30 text-xs text-accent animate-fade-in">
            <Loader2 className="h-4 w-4 animate-spin shrink-0" />
            <span>{statusStep}</span>
          </div>
        )}

        {/* Error Alert */}
        {errorMessage && (
          <div className="flex items-start gap-2.5 p-3 rounded-md bg-severity-critical/10 border border-severity-critical/30 text-xs text-red-300 animate-fade-in">
            <AlertCircle className="h-4 w-4 text-severity-critical shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-red-200">Connection Failed</p>
              <p className="mt-0.5 text-slate-300">{errorMessage}</p>
            </div>
          </div>
        )}

        {/* Success Alert */}
        {successMessage && (
          <div className="flex items-center gap-2.5 p-3 rounded-md bg-status-connected/10 border border-status-connected/30 text-xs text-status-connected animate-fade-in">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span>{successMessage}</span>
          </div>
        )}
      </form>
    </Modal>
  );
}
