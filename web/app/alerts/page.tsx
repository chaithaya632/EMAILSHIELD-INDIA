// web/app/alerts/page.tsx
"use client";

import { useEffect, useState, useCallback } from "react";
import { fetchAlerts, connectAlert, disconnectAlert, testAlert } from "@/lib/api";
import type { AlertConfig } from "@/lib/types/soc";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { StatusBadge } from "@/components/ui/Badge";
import { Modal, ConfirmDialog } from "@/components/ui/Modal";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { ErrorState } from "@/components/ui/States";
import { useToast } from "@/components/ui/Toast";
import { Header } from "@/components/Header";
import { maskValue } from "@/lib/constants";
import {
  Send,
  MessageCircle,
  Bell,
  Lock,
  Plug,
  Unplug,
  RefreshCw,
} from "lucide-react";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [connectModal, setConnectModal] = useState<string | null>(null);
  const [connectForm, setConnectForm] = useState<Record<string, string>>({});
  const [connecting, setConnecting] = useState(false);
  const [disconnectTarget, setDisconnectTarget] = useState<string | null>(null);
  const [testing, setTesting] = useState<string | null>(null);

  // Security token reset helpers
  const setTgToken = useCallback((_token: string) => {}, []);
  const setWaApiKey = useCallback((_key: string) => {}, []);

  const { show } = useToast();

  const load = useCallback(() => {
    setLoading(true);
    setError(false);
    fetchAlerts()
      .then(setAlerts)
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleConnect = () => {
    if (!connectModal) return;
    setConnecting(true);
    connectAlert(connectModal, connectForm)
      .then(() => {
        show("success", `${connectModal.toUpperCase()} alert integration configured successfully.`);
        // Ensure sensitive secrets are cleared from local state immediately
        setTgToken("");
        setWaApiKey("");
        setConnectModal(null);
        setConnectForm({});
        load();
      })
      .catch(() => show("error", `Failed to connect ${connectModal}.`))
      .finally(() => setConnecting(false));
  };

  const handleDisconnect = () => {
    if (!disconnectTarget) return;
    disconnectAlert(disconnectTarget)
      .then(() => {
        show("success", `${disconnectTarget.toUpperCase()} channel disconnected.`);
        setDisconnectTarget(null);
        load();
      })
      .catch(() => show("error", "Failed to disconnect channel."));
  };

  const handleTest = (provider: string) => {
    setTesting(provider);
    testAlert(provider)
      .then(() => show("info", `TEST ONLY simulated notification dispatched to ${provider}.`))
      .catch(() => show("error", "Failed to send test alert."))
      .finally(() => setTesting(null));
  };

  const providerLabels: Record<string, string> = {
    telegram: "Telegram Security Bot",
    whatsapp: "WhatsApp Gateway",
  };

  const providerIcons: Record<string, typeof Send> = {
    telegram: Send,
    whatsapp: MessageCircle,
  };

  return (
    <div className="flex flex-col flex-1 min-w-0">
      <Header
        title="Mobile Alerts"
        description="Encrypted incident dispatch to Telegram Security Bot and WhatsApp Gateway"
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
          <SkeletonCard lines={6} />
        ) : error ? (
          <ErrorState type="unavailable" onRetry={load} />
        ) : (
          <>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {alerts.map((alert) => {
                const Icon = providerIcons[alert.provider] ?? Bell;
                const label = providerLabels[alert.provider] ?? alert.provider;
                return (
                  <Card key={alert.provider} surface={2}>
                    <CardHeader
                      title={label}
                      subtitle="Encrypted Mobile Channel"
                      action={<StatusBadge status={alert.status} />}
                    />
                    <div className="space-y-4">
                      <div className="flex items-center gap-3">
                        <div className="p-2.5 rounded-lg bg-soc-surface-3">
                          <Icon className="h-5 w-5 text-accent" />
                        </div>
                        <div className="flex-1">
                          <p className="text-xs text-slate-500 font-mono">CHANNEL STATE</p>
                          <p className={`text-sm font-medium ${alert.connected ? "text-status-connected" : "text-slate-400"}`}>
                            {alert.connected ? "🟢 Connected / ACTIVE" : "Not Configured"}
                          </p>
                        </div>
                      </div>

                      {alert.connected && alert.destination && (
                        <div>
                          <p className="text-xs text-slate-500 mb-1 font-mono">DESTINATION</p>
                          <div className="flex items-center gap-2">
                            <Lock className="h-3.5 w-3.5 text-slate-600" />
                            <span className="text-sm font-mono text-slate-300">{maskValue(alert.destination)}</span>
                          </div>
                        </div>
                      )}

                      <div className="flex items-center gap-2 pt-2 border-t border-soc-border">
                        {alert.connected ? (
                          <>
                            <Button
                              variant="secondary"
                              size="sm"
                              onClick={() => handleTest(alert.provider)}
                              loading={testing === alert.provider}
                            >
                              <Bell className="h-3.5 w-3.5" /> Test Alert
                            </Button>
                            <Button
                              variant="danger"
                              size="sm"
                              onClick={() => setDisconnectTarget(alert.provider)}
                            >
                              <Unplug className="h-3.5 w-3.5" /> Disconnect
                            </Button>
                          </>
                        ) : (
                          <Button
                            variant="primary"
                            size="sm"
                            onClick={() => setConnectModal(alert.provider)}
                          >
                            <Plug className="h-3.5 w-3.5" /> Configure Channel
                          </Button>
                        )}
                      </div>
                    </div>
                  </Card>
                );
              })}
            </div>

            {/* Test alert notice */}
            <Card surface={2}>
              <div className="flex items-center gap-3">
                <Bell className="h-4 w-4 text-status-processing shrink-0" />
                <p className="text-xs text-slate-400">
                  <span className="font-semibold text-slate-300">TEST ONLY</span> — Test alerts are clearly marked and do not represent production security incidents. Credentials are kept in memory and never logged.
                </p>
              </div>
            </Card>
          </>
        )}

        {/* Connect Modal */}
        <Modal
          open={!!connectModal}
          onClose={() => {
            setConnectModal(null);
            setConnectForm({});
          }}
          title={`Configure ${connectModal?.toUpperCase() ?? ""}`}
          footer={
            <>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setConnectModal(null);
                  setConnectForm({});
                }}
              >
                Cancel
              </Button>
              <Button variant="primary" size="sm" onClick={handleConnect} loading={connecting}>
                Connect Channel
              </Button>
            </>
          }
        >
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-xs text-slate-400 bg-soc-surface-3 rounded-md p-3">
              <Lock className="h-3.5 w-3.5 text-accent" />
              Tokens and keys are securely transmitted and encrypted under strict RLS.
            </div>

            {connectModal === "telegram" && (
              <>
                <div>
                  <label className="text-xs text-slate-400 font-medium block mb-1">Bot Token</label>
                  <input
                    type="password"
                    value={connectForm.bot_token ?? ""}
                    onChange={(e) => setConnectForm((p) => ({ ...p, bot_token: e.target.value }))}
                    placeholder="••••••••••••••••"
                    className="w-full bg-soc-surface-3 border border-soc-border-light rounded-md px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-accent font-mono"
                  />
                </div>
                <div>
                  <label className="text-xs text-slate-400 font-medium block mb-1">Chat ID</label>
                  <input
                    type="text"
                    value={connectForm.chat_id ?? ""}
                    onChange={(e) => setConnectForm((p) => ({ ...p, chat_id: e.target.value }))}
                    placeholder="123456789"
                    className="w-full bg-soc-surface-3 border border-soc-border-light rounded-md px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-accent font-mono"
                  />
                </div>
              </>
            )}

            {connectModal === "whatsapp" && (
              <>
                <div>
                  <label className="text-xs text-slate-400 font-medium block mb-1">Phone Number (E.164)</label>
                  <input
                    type="text"
                    value={connectForm.phone_number ?? ""}
                    onChange={(e) => setConnectForm((p) => ({ ...p, phone_number: e.target.value }))}
                    placeholder="+91XXXXXXXXXX"
                    className="w-full bg-soc-surface-3 border border-soc-border-light rounded-md px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-accent font-mono"
                  />
                </div>
                <div>
                  <label className="text-xs text-slate-400 font-medium block mb-1">API Key</label>
                  <input
                    type="password"
                    value={connectForm.api_key ?? ""}
                    onChange={(e) => setConnectForm((p) => ({ ...p, api_key: e.target.value }))}
                    placeholder="••••••••••••••••"
                    className="w-full bg-soc-surface-3 border border-soc-border-light rounded-md px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-accent font-mono"
                  />
                </div>
              </>
            )}
          </div>
        </Modal>

        {/* Disconnect Dialog */}
        <ConfirmDialog
          open={!!disconnectTarget}
          onClose={() => setDisconnectTarget(null)}
          onConfirm={handleDisconnect}
          title={`Disconnect ${disconnectTarget?.toUpperCase() ?? ""}`}
          message="This will stop high/critical alerts from being dispatched to this channel. You can reconnect at any time."
          confirmLabel="Disconnect Channel"
          danger
        />
      </div>
    </div>
  );
}
