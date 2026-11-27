import React from "react";

interface SecurityAnalyticsChartsProps {
  vulnerabilities?: any[];
  rawHeaders?: Record<string, any>;
  sslValid?: boolean;
  scanHistory?: any[];
}

export const SecurityAnalyticsCharts: React.FC<SecurityAnalyticsChartsProps> = ({
  vulnerabilities = [],
  rawHeaders = {},
  sslValid = false,
  scanHistory = [],
}) => {
  const safeVulns = Array.isArray(vulnerabilities) ? vulnerabilities : [];
  const safeHeaders =
    rawHeaders && typeof rawHeaders === "object" ? rawHeaders : {};
  const safeHistory = Array.isArray(scanHistory) ? scanHistory : [];

  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const v of safeVulns) {
    const s = String(v?.severity || "low").toLowerCase();
    if (s in counts) {
      counts[s as keyof typeof counts] += 1;
    } else {
      counts.low += 1;
    }
  }

  const total = Math.max(1, safeVulns.length);
  const headerCount = Object.keys(safeHeaders).length;

  const bars = [
    {
      label: "Critical",
      value: counts.critical,
      pct: Math.round((counts.critical / total) * 100),
      barClass: "bg-red-500",
      textClass: "text-red-400",
    },
    {
      label: "High",
      value: counts.high,
      pct: Math.round((counts.high / total) * 100),
      barClass: "bg-amber-400",
      textClass: "text-amber-300",
    },
    {
      label: "Medium",
      value: counts.medium,
      pct: Math.round((counts.medium / total) * 100),
      barClass: "bg-cyan-400",
      textClass: "text-cyan-300",
    },
    {
      label: "Low / Info",
      value: counts.low + counts.info,
      pct: Math.round(((counts.low + counts.info) / total) * 100),
      barClass: "bg-emerald-400",
      textClass: "text-emerald-300",
    },
  ];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div className="p-4 rounded-xl bg-[#050a14] border border-slate-800 space-y-3">
        <div className="flex items-center justify-between text-xs">
          <span className="font-bold text-white">Severity Distribution</span>
          <span className="font-mono text-cyan-400">
            {safeVulns.length} Total Issues
          </span>
        </div>

        <div className="space-y-2.5">
          {bars.map((b) => (
            <div key={b.label} className="space-y-1 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-300">{b.label}</span>
                <span className={`font-mono font-semibold ${b.textClass}`}>
                  {b.value} ({safeVulns.length ? `${b.pct}%` : "0%"})
                </span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className={`h-full ${b.barClass} transition-all duration-500`}
                  style={{ width: `${safeVulns.length ? b.pct : 0}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="p-4 rounded-xl bg-[#050a14] border border-slate-800 flex flex-col justify-between space-y-3">
        <div className="flex items-center justify-between text-xs">
          <span className="font-bold text-white">Telemetry Snapshot</span>
          <span className="font-mono text-slate-400">
            Audits in Session: {safeHistory.length}
          </span>
        </div>

        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="p-3 rounded-lg bg-[#0b1322] border border-slate-800">
            <div className="text-slate-400">TLS / SSL Status</div>
            <div
              className={`font-mono font-bold mt-1 ${
                sslValid ? "text-emerald-400" : "text-amber-400"
              }`}
            >
              {sslValid ? "Verified / Active" : "Check Required"}
            </div>
          </div>

          <div className="p-3 rounded-lg bg-[#0b1322] border border-slate-800">
            <div className="text-slate-400">HTTP Headers Captured</div>
            <div className="font-mono font-bold text-cyan-400 mt-1">
              {headerCount} headers
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};