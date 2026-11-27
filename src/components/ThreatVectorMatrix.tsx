import React, { useState } from "react";
import { ShieldAlert, Network, Lock, Server, CheckCircle2, AlertTriangle } from "lucide-react";

interface ThreatVectorMatrixProps {
  reconnaissance: any;
  vulnerabilities: any[];
}

export const ThreatVectorMatrix: React.FC<ThreatVectorMatrixProps> = ({
  reconnaissance = {},
  vulnerabilities = [],
}) => {
  const [selectedNode, setSelectedNode] = useState<string>("ports");

  const openPorts = reconnaissance.openPorts || [];
  const sslValid = reconnaissance.sslValid || false;
  const tlsVersion = reconnaissance.tlsVersion || "N/A";

  return (
    <div className="p-5 rounded-xl bg-slate-950/90 border border-slate-800/90 shadow-xl space-y-4 my-6">
      <div className="flex flex-wrap justify-between items-center gap-2 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2">
          <Network className="w-5 h-5 text-cyan-400" />
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
            Interactive Attack Surface & Threat Vector Matrix
          </h3>
        </div>
        <span className="text-xs font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2.5 py-1 rounded">
          Live Probe Node Active
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        {/* Node 1: Ports */}
        <button
          onClick={() => setSelectedNode("ports")}
          className={`p-3.5 rounded-lg border text-left transition-all ${
            selectedNode === "ports"
              ? "bg-purple-950/40 border-purple-500/60 shadow-[0_0_15px_rgba(168,85,247,0.15)]"
              : "bg-slate-900/60 border-slate-800 hover:border-slate-700"
          }`}
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-semibold text-purple-300 flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5" /> TCP Ports
            </span>
            <span className="text-xs font-mono text-purple-400">
              {openPorts.length} Open
            </span>
          </div>
          <p className="text-[11px] text-slate-400">
            Socket listener verification
          </p>
        </button>

        {/* Node 2: TLS/SSL */}
        <button
          onClick={() => setSelectedNode("tls")}
          className={`p-3.5 rounded-lg border text-left transition-all ${
            selectedNode === "tls"
              ? "bg-emerald-950/40 border-emerald-500/60 shadow-[0_0_15px_rgba(16,185,129,0.15)]"
              : "bg-slate-900/60 border-slate-800 hover:border-slate-700"
          }`}
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-semibold text-emerald-300 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5" /> Transport TLS
            </span>
            {sslValid ? (
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
            )}
          </div>
          <p className="text-[11px] text-slate-400">{tlsVersion} Cipher Stack</p>
        </button>

        {/* Node 3: Vulnerabilities */}
        <button
          onClick={() => setSelectedNode("vulns")}
          className={`p-3.5 rounded-lg border text-left transition-all ${
            selectedNode === "vulns"
              ? "bg-red-950/40 border-red-500/60 shadow-[0_0_15px_rgba(239,68,68,0.15)]"
              : "bg-slate-900/60 border-slate-800 hover:border-slate-700"
          }`}
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-semibold text-red-300 flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5" /> Risk Vectors
            </span>
            <span className="text-xs font-mono text-red-400">
              {vulnerabilities.length} Found
            </span>
          </div>
          <p className="text-[11px] text-slate-400">Active header flaws</p>
        </button>

        {/* Node 4: Security.txt */}
        <button
          onClick={() => setSelectedNode("compliance")}
          className={`p-3.5 rounded-lg border text-left transition-all ${
            selectedNode === "compliance"
              ? "bg-cyan-950/40 border-cyan-500/60 shadow-[0_0_15px_rgba(6,182,212,0.15)]"
              : "bg-slate-900/60 border-slate-800 hover:border-slate-700"
          }`}
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-semibold text-cyan-300 flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" /> Disclosure
            </span>
            <span className="text-xs font-mono text-cyan-400">
              {reconnaissance.securityTxt ? "RFC 9116" : "Not Found"}
            </span>
          </div>
          <p className="text-[11px] text-slate-400">Security policy check</p>
        </button>
      </div>

      {/* Dynamic Node Detail Box */}
      <div className="p-4 rounded-lg bg-black/60 border border-slate-800 font-mono text-xs text-slate-300 space-y-2">
        {selectedNode === "ports" && (
          <div>
            <span className="text-purple-400 font-bold block mb-1">
              &gt;&gt; ACTIVE TCP SOCKET PORTS ANALYSIS:
            </span>
            <p className="text-slate-400 font-sans text-xs">
              Discovered open service endpoints:{" "}
              <strong className="text-purple-300 font-mono">
                {openPorts.length > 0 ? openPorts.join(", ") : "No standard web ports detected"}
              </strong>
              . Open ports increase attack surface if unmanaged enterprise services or outdated daemons are exposed.
            </p>
          </div>
        )}

        {selectedNode === "tls" && (
          <div>
            <span className="text-emerald-400 font-bold block mb-1">
              &gt;&gt; TRANSPORT LAYER SECURITY (TLS/SSL) TELEMETRY:
            </span>
            <p className="text-slate-400 font-sans text-xs">
              Issuer: <span className="text-slate-200">{reconnaissance.sslIssuer || "N/A"}</span> | Expiry:{" "}
              <span className="text-slate-200">{reconnaissance.sslExpiry || "N/A"}</span> ({reconnaissance.sslDays ?? "N/A"} days remaining). Protocol handshake verified via {tlsVersion}.
            </p>
          </div>
        )}

        {selectedNode === "vulns" && (
          <div>
            <span className="text-red-400 font-bold block mb-1">
              &gt;&gt; ATTACK VECTOR FINDINGS SUMMARY:
            </span>
            <p className="text-slate-400 font-sans text-xs">
              {vulnerabilities.length > 0
                ? `${vulnerabilities.length} header or protocol misconfigurations identified. Attackers can leverage missing CSP or HSTS policies for injection/mitm exploitation.`
                : "No high-risk vulnerability vectors detected in current profile."}
            </p>
          </div>
        )}

        {selectedNode === "compliance" && (
          <div>
            <span className="text-cyan-400 font-bold block mb-1">
              &gt;&gt; RFC 9116 SECURITY DISCLOSURE:
            </span>
            <p className="text-slate-400 font-sans text-xs">
              {reconnaissance.securityTxt
                ? "Valid .well-known/security.txt file is present, enabling responsible vulnerability reporting."
                : "security.txt is missing. Researchers lack structured contact info for reporting security flaws."}
            </p>
          </div>
        )}
      </div>
    </div>
  );
};