// web/app/intel/page.tsx
"use client";

import { useState } from "react";
import { fetchIntel } from "@/lib/api";
import type { IntelResult } from "@/lib/types/soc";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { SeverityBadge } from "@/components/ui/Badge";
import { FilterBar, FilterChip } from "@/components/ui/SearchBar";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { EmptyState, ErrorState } from "@/components/ui/States";
import { EvidenceBlock } from "@/components/ui/EvidenceBlock";
import { Header } from "@/components/Header";
import { Globe, Search, Lock, MapPin, Server, Shield, Network } from "lucide-react";

const INDICATOR_TYPES = [
  { key: "ip", label: "IP" },
  { key: "domain", label: "Domain" },
  { key: "url", label: "URL" },
  { key: "hash", label: "Hash" },
  { key: "email", label: "Email" },
];

export default function IntelPage() {
  const [query, setQuery] = useState("");
  const [type, setType] = useState("ip");
  const [result, setResult] = useState<IntelResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [searched, setSearched] = useState(false);

  const handleSearch = () => {
    if (!query.trim()) return;
    setLoading(true);
    setError(false);
    setSearched(true);
    fetchIntel(query.trim(), type)
      .then(setResult)
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  };

  return (
    <div className="flex flex-col flex-1 min-w-0">
      <Header
        title="IOC / URL Intelligence"
        description="Indicator reputation, GeoIP, RDAP, and DNS lookup"
      />

      <div className="p-4 lg:p-6 space-y-6 flex-1 animate-fade-in">
        {/* Search Bar */}
        <Card surface={2}>
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500 pointer-events-none" />
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                  placeholder="Enter IP, domain, URL, hash, or email address..."
                  className="w-full bg-soc-surface border border-soc-border-light rounded-md pl-9 pr-4 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-accent font-mono transition-colors"
                />
              </div>
              <Button variant="primary" size="md" onClick={handleSearch} loading={loading}>
                Search
              </Button>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-medium">Type:</span>
              <FilterBar>
                {INDICATOR_TYPES.map((t) => (
                  <FilterChip
                    key={t.key}
                    label={t.label}
                    active={type === t.key}
                    onClick={() => setType(t.key)}
                  />
                ))}
              </FilterBar>
            </div>
          </div>
        </Card>

        {/* Results */}
        {loading && <SkeletonCard lines={8} />}
        {error && <ErrorState type="connection" onRetry={handleSearch} />}
        {!loading && !error && !result && searched && (
          <EmptyState
            icon={<Globe className="h-8 w-8" />}
            title="No intelligence found."
            message="No threat data or reputation records found for this indicator."
          />
        )}

        {result && (
          <div className="space-y-4">
            {/* Overview Card */}
            <Card surface={2}>
              <CardHeader
                title="Indicator Overview"
                subtitle="Consolidated threat reputation"
                action={<SeverityBadge severity={result.risk} size="md" />}
              />
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div>
                  <p className="text-xs text-slate-500">Indicator</p>
                  <p className="text-sm text-slate-200 font-mono mt-0.5 truncate">{result.indicator}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500">Type</p>
                  <p className="text-sm text-slate-200 uppercase font-mono mt-0.5">{result.type}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500">Reputation</p>
                  <p className="text-sm text-slate-200 mt-0.5">{result.reputation ?? "Unknown"}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500">Access Mode</p>
                  <p className="text-xs text-status-connected flex items-center gap-1 mt-1 font-mono">
                    <Lock className="h-3 w-3" /> Read-Only Verified
                  </p>
                </div>
              </div>
            </Card>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* GeoIP */}
              {result.geoip && (
                <Card surface={2}>
                  <CardHeader title="Geolocation (Network Infrastructure)" subtitle="Autonomous System & GeoIP" />
                  <div className="space-y-2 text-sm">
                    <div className="flex items-center gap-2">
                      <MapPin className="h-4 w-4 text-slate-500" />
                      <span className="text-slate-300">
                        {result.geoip.city ? `${result.geoip.city}, ` : ""}
                        {result.geoip.country}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Server className="h-4 w-4 text-slate-500" />
                      <span className="text-slate-300 font-mono text-xs">{result.geoip.isp}</span>
                    </div>
                    <p className="text-xs text-slate-500 font-mono">
                      Coordinates: {result.geoip.lat}, {result.geoip.lon}
                    </p>
                  </div>
                </Card>
              )}

              {/* RDAP / Whois */}
              {result.rdap && (
                <Card surface={2}>
                  <CardHeader title="RDAP / Domain Registration" subtitle="Registrar and delegation info" />
                  <div className="space-y-2 text-sm">
                    <p className="text-slate-300">
                      <span className="text-slate-500 text-xs">Registrar:</span> {result.rdap.registrar}
                    </p>
                    <p className="text-slate-300">
                      <span className="text-slate-500 text-xs">Registered:</span>{" "}
                      {new Date(result.rdap.created).toLocaleDateString()}
                    </p>
                    <p className="text-slate-300">
                      <span className="text-slate-500 text-xs">Expires:</span>{" "}
                      {new Date(result.rdap.expires).toLocaleDateString()}
                    </p>
                    <div className="flex gap-1 flex-wrap mt-1">
                      {result.rdap.status.map((s, i) => (
                        <span key={i} className="text-[0.625rem] px-1.5 py-0.5 rounded bg-soc-surface-3 text-slate-400 font-mono">
                          {s}
                        </span>
                      ))}
                    </div>
                  </div>
                </Card>
              )}

              {/* DNS */}
              {result.dns && result.dns.length > 0 && (
                <Card surface={2}>
                  <CardHeader title="DNS Records" subtitle="Domain Name System delegation" />
                  <div className="space-y-1.5">
                    {result.dns.map((rec, i) => (
                      <div key={i} className="flex items-center gap-2 text-sm">
                        <Network className="h-3.5 w-3.5 text-slate-500 shrink-0" />
                        <span className="text-xs font-mono text-slate-500 uppercase w-12 shrink-0">{rec.type}</span>
                        <span className="text-slate-200 font-mono truncate text-xs">{rec.value}</span>
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {/* Authentication */}
              {result.authentication && (
                <Card surface={2}>
                  <CardHeader title="Authentication" subtitle="Email cryptographic records" />
                  <div className="flex items-center gap-3">
                    <Shield className="h-5 w-5 text-slate-500" />
                    <div className="text-xs space-y-1 font-mono">
                      <p className="text-slate-300">
                        SPF: <span className="text-slate-400">{result.authentication.spf}</span>
                      </p>
                      <p className="text-slate-300">
                        DKIM: <span className="text-slate-400">{result.authentication.dkim}</span>
                      </p>
                      <p className="text-slate-300">
                        DMARC: <span className="text-slate-400">{result.authentication.dmarc}</span>
                      </p>
                    </div>
                  </div>
                </Card>
              )}
            </div>

            {/* Evidence */}
            {result.evidence && result.evidence.length > 0 && (
              <Card surface={2}>
                <CardHeader title="Evidence" subtitle="Supporting evidence for this indicator" />
                <EvidenceBlock items={result.evidence} />
              </Card>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
