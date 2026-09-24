// web/app/settings/page.tsx
"use client";

import { useEffect, useState, useCallback } from "react";
import { fetchSettings, updateSettings, disconnectMailbox } from "@/lib/api";
import type { SettingsData } from "@/lib/types/soc";
import { Card, CardHeader } from "@/components/ui/Card";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { ErrorState } from "@/components/ui/States";
import { Header } from "@/components/Header";
import { ConnectMailboxModal } from "@/components/live-mail/ConnectMailboxModal";
import { ConfirmDialog } from "@/components/ui/Modal";
import { maskValue } from "@/lib/constants";
import {
  User,
  Mail,
  Server,
  Lock,
  Shield,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Plus,
  Unplug,
} from "lucide-react";

export default function SettingsPage() {
  const [data, setData] = useState<SettingsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [saving, setSaving] = useState(false);

  // Mailbox Modals
  const [connectModalOpen, setConnectModalOpen] = useState(false);
  const [disconnectConfirmOpen, setDisconnectConfirmOpen] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    setError(false);
    fetchSettings()
      .then(setData)
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const toggleWorker = async () => {
    if (!data) return;
    setSaving(true);
    const nextState = !data.live_mail.worker_enabled;
    try {
      await updateSettings("live_mail", { worker_enabled: nextState });
      setData((prev) =>
        prev
          ? {
              ...prev,
              live_mail: { ...prev.live_mail, worker_enabled: nextState },
            }
          : null
      );
    } catch {
      // Revert on failure
    } finally {
      setSaving(false);
    }
  };

  const handleDisconnect = async () => {
    setDisconnecting(true);
    try {
      await disconnectMailbox();
      setDisconnectConfirmOpen(false);
      load();
    } catch {
      // Revert
    } finally {
      setDisconnecting(false);
    }
  };

  return (
    <div className="flex flex-col flex-1 min-w-0">
      <Header
        title="Settings"
        description="Mailbox monitoring, alerting channels, and platform security posture"
        actions={
          <button
            onClick={load}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-soc-surface-2 text-slate-300 hover:text-white hover:bg-soc-surface-3 transition-colors border border-soc-border"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            <span>Refresh</span>
          </button>
        }
      />

      <div className="p-4 lg:p-6 space-y-6 flex-1 animate-fade-in">
        {loading ? (
          <SkeletonCard lines={8} />
        ) : error || !data ? (
          <ErrorState type="unavailable" onRetry={load} />
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* User Profile */}
            <Card surface={2}>
              <CardHeader title="Operator Profile" subtitle="Authenticated SOC investigator" />
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 bg-soc-surface border border-soc-border rounded-md">
                  <div className="flex items-center gap-3">
                    <User className="h-4 w-4 text-accent" />
                    <span className="text-sm text-slate-200">Name</span>
                  </div>
                  <span className="text-xs text-slate-300 font-mono">{data.profile.name}</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-soc-surface border border-soc-border rounded-md">
                  <div className="flex items-center gap-3">
                    <Mail className="h-4 w-4 text-accent" />
                    <span className="text-sm text-slate-200">Email</span>
                  </div>
                  <span className="text-xs text-slate-300 font-mono">{data.profile.email}</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-soc-surface border border-soc-border rounded-md">
                  <div className="flex items-center gap-3">
                    <Shield className="h-4 w-4 text-accent" />
                    <span className="text-sm text-slate-200">Role</span>
                  </div>
                  <span className="text-xs text-slate-300 font-mono">{data.profile.role}</span>
                </div>
              </div>
            </Card>

            {/* Live Mail Configuration */}
            <Card surface={2}>
              <CardHeader title="Live Mail Configuration" subtitle="Mailbox monitoring settings" />
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 bg-soc-surface border border-soc-border rounded-md flex-wrap gap-2">
                  <div className="flex items-center gap-3">
                    <Mail className="h-4 w-4 text-slate-400" />
                    <span className="text-sm text-slate-200">Mailbox</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {data.live_mail.mailbox_configured ? (
                      <>
                        <span className="text-xs text-slate-300 font-mono">
                          {maskValue(data.live_mail.mailbox_address ?? "")}
                        </span>
                        <CheckCircle2 className="h-4 w-4 text-status-connected" />
                        <button
                          onClick={() => setConnectModalOpen(true)}
                          className="text-[11px] px-2 py-1 rounded bg-soc-surface-2 text-slate-300 hover:text-white border border-soc-border"
                        >
                          Change
                        </button>
                        <button
                          onClick={() => setDisconnectConfirmOpen(true)}
                          className="text-[11px] px-2 py-1 rounded bg-rose-500/10 text-rose-300 hover:bg-rose-500/20 border border-rose-500/30"
                        >
                          <Unplug className="h-3 w-3" />
                        </button>
                      </>
                    ) : (
                      <>
                        <span className="text-xs text-slate-500">Not configured</span>
                        <XCircle className="h-4 w-4 text-status-error" />
                        <button
                          onClick={() => setConnectModalOpen(true)}
                          className="flex items-center gap-1 text-xs px-2.5 py-1 rounded bg-accent text-white hover:bg-accent-hover font-medium shadow-sm"
                        >
                          <Plus className="h-3 w-3" />
                          <span>Connect</span>
                        </button>
                      </>
                    )}
                  </div>
                </div>

                <div className="flex items-center justify-between p-3 bg-soc-surface border border-soc-border rounded-md">
                  <div className="flex items-center gap-3">
                    <Server className="h-4 w-4 text-slate-400" />
                    <span className="text-sm text-slate-200">Worker Daemon</span>
                  </div>
                  <button
                    onClick={toggleWorker}
                    disabled={saving}
                    className={`text-xs px-3 py-1.5 rounded-md font-medium transition-colors ${
                      data.live_mail.worker_enabled
                        ? "bg-status-connected/20 text-status-connected border border-status-connected/40 hover:bg-status-connected/30"
                        : "bg-soc-surface-3 text-slate-400 border border-soc-border hover:text-slate-200"
                    }`}
                  >
                    {data.live_mail.worker_enabled ? "RUNNING" : "STOPPED"}
                  </button>
                </div>
              </div>
            </Card>

            {/* Security Posture */}
            <Card surface={2} className="lg:col-span-2">
              <CardHeader title="Security Architecture & RLS Posture" subtitle="Platform security guarantees" />
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="flex items-center justify-between p-3 bg-soc-surface border border-soc-border rounded-md">
                  <div className="flex items-center gap-3">
                    <Shield className="h-4 w-4 text-status-connected" />
                    <span className="text-xs text-slate-200">Row Level Security</span>
                  </div>
                  <span className="text-xs text-status-connected font-mono font-medium">ENFORCED</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-soc-surface border border-soc-border rounded-md">
                  <div className="flex items-center gap-3">
                    <Lock className="h-4 w-4 text-status-connected" />
                    <span className="text-xs text-slate-200">Credential Vault</span>
                  </div>
                  <span className="text-xs text-status-connected font-mono font-medium">ACTIVE</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-soc-surface border border-soc-border rounded-md">
                  <div className="flex items-center gap-3">
                    <Shield className="h-4 w-4 text-status-connected" />
                    <span className="text-xs text-slate-200">Tenant Isolation</span>
                  </div>
                  <span className="text-xs text-status-connected font-mono font-medium">STRICT</span>
                </div>
              </div>
              <p className="text-xs text-slate-500 flex items-center gap-1.5 mt-3 font-mono">
                <Lock className="h-3 w-3 text-accent" /> service_role keys, master keys, and JWT tokens are never exposed in browser code.
              </p>
            </Card>
          </div>
        )}
      </div>

      {/* Connect Mailbox Modal */}
      <ConnectMailboxModal
        open={connectModalOpen}
        onClose={() => setConnectModalOpen(false)}
        onSuccess={load}
      />

      {/* Disconnect Mailbox Confirmation */}
      <ConfirmDialog
        open={disconnectConfirmOpen}
        onClose={() => setDisconnectConfirmOpen(false)}
        onConfirm={handleDisconnect}
        title="Disconnect Mailbox"
        message="Are you sure you want to disconnect this mailbox? Live Mail monitoring will be immediately halted."
        confirmLabel="Disconnect Mailbox"
        danger
        loading={disconnecting}
      />
    </div>
  );
}
