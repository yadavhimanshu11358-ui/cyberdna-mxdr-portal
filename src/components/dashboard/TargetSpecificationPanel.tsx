import React, { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Shield,
  Globe,
  Server,
  Cpu,
  Zap,
  CheckCircle2,
  Lock,
  Activity,
  Database,
  Play,
} from "lucide-react";

interface TargetSpecificationPanelProps {
  onScanInitiate: (targetData: {
    targetType: string;
    targetValue: string;
    assessmentProfile: string;
    configOptions: Record<string, any>;
  }) => void;
}

const TargetSpecificationPanel: React.FC<TargetSpecificationPanelProps> = ({
  onScanInitiate,
}) => {
  const [targetType, setTargetType] = useState<string>("domain");
  const [targetValue, setTargetValue] = useState<string>("");
  const [assessmentProfile, setAssessmentProfile] = useState<string>("rapid");
  const [portRange, setPortRange] = useState<string>("top100");
  const [authHeader, setAuthHeader] = useState<string>("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onScanInitiate({
      targetType,
      targetValue,
      assessmentProfile,
      configOptions: {
        portRange,
        authHeader,
      },
    });
  };

  return (
    <Card className="border-slate-800 bg-[#0b1322] text-slate-100 overflow-hidden shadow-xl">
      <div className="bg-gradient-to-r from-[#0a2540] to-[#0e7490] px-5 py-4 border-b border-cyan-500/20">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-slate-950/50 border border-cyan-400/30">
            <Shield className="h-5 w-5 text-cyan-300" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white tracking-tight">
              CyberDNA Scanner
            </h2>
            <p className="text-[11px] text-cyan-100/80">
              Attack Surface &amp; Telemetry Engine
            </p>
          </div>
        </div>

        <div className="flex flex-wrap gap-1.5 mt-3">
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-slate-950/60 text-emerald-300 border border-emerald-400/30">
            <Zap className="w-2.5 h-2.5" /> Enterprise-Grade
          </span>
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-slate-950/60 text-cyan-200 border border-cyan-400/30">
            <Cpu className="w-2.5 h-2.5" /> AI-Powered
          </span>
        </div>
      </div>

      <CardContent className="p-5">
        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Target Classification */}
          <div>
            <label className="flex items-center gap-1.5 text-xs font-semibold text-slate-300 mb-2">
              <Globe className="w-3.5 h-3.5 text-cyan-400" />
              Target Classification
            </label>
            <div className="grid grid-cols-3 gap-2">
              {[
                { id: "domain", label: "Domain" },
                { id: "ipv4", label: "IPv4" },
                { id: "ipv6", label: "IPv6" },
              ].map((type) => {
                const active = targetType === type.id;
                return (
                  <button
                    key={type.id}
                    type="button"
                    onClick={() => setTargetType(type.id)}
                    className={`h-9 px-2.5 rounded-lg text-xs font-semibold border transition-colors ${
                      active
                        ? "bg-[#0284c7] text-white border-[#0284c7]"
                        : "bg-[#050a14] text-slate-300 border-slate-800 hover:border-slate-700"
                    }`}
                  >
                    {type.label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Target Input */}
          <div>
            <label className="flex items-center gap-1.5 text-xs font-semibold text-slate-300 mb-1.5">
              <Server className="w-3.5 h-3.5 text-cyan-400" />
              {targetType === "domain"
                ? "Target Domain"
                : targetType === "ipv4"
                  ? "Target IPv4 Address"
                  : "Target IPv6 Address"}
            </label>
            <input
              type="text"
              value={targetValue}
              onChange={(e) => setTargetValue(e.target.value)}
              placeholder={
                targetType === "domain"
                  ? "example.com"
                  : targetType === "ipv4"
                    ? "192.168.1.1"
                    : "2001:db8::1"
              }
              required
              className="w-full h-9 px-3.5 rounded-lg bg-[#050a14] border border-slate-700 text-xs font-mono text-white placeholder:text-slate-500 focus:outline-none focus:border-[#0284c7]"
            />
          </div>

          {/* Assessment Profile */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">
              Assessment Profile
            </label>
            <select
              value={assessmentProfile}
              onChange={(e) => setAssessmentProfile(e.target.value)}
              className="w-full h-9 px-3 rounded-lg bg-[#050a14] border border-slate-700 text-xs font-medium text-white focus:outline-none focus:border-[#0284c7]"
            >
              <option value="rapid">Rapid Assessment (Headers &amp; TLS)</option>
              <option value="comprehensive">
                Comprehensive Audit (Cookies &amp; Policies)
              </option>
              <option value="fullPenTest">
                Full MXDR Deep Audit (CORS &amp; Disclosure)
              </option>
            </select>

            <div className="grid grid-cols-3 gap-1.5 mt-2 p-1 rounded-lg bg-[#050a14] border border-slate-800">
              {[
                { id: "rapid", label: "Rapid" },
                { id: "comprehensive", label: "Deep" },
                { id: "fullPenTest", label: "Full Audit" },
              ].map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setAssessmentProfile(tab.id)}
                  className={`h-8 rounded-md text-[11px] font-semibold transition-colors ${
                    assessmentProfile === tab.id
                      ? "bg-[#0284c7] text-white"
                      : "text-slate-400 hover:text-white"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          {/* Assessment Modules */}
          <div className="p-3.5 rounded-xl bg-[#050a14] border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-cyan-400" />
                Assessment Modules
              </span>
              <span className="text-[11px] font-mono font-semibold text-emerald-400">
                6 active
              </span>
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">
                Port Verification Scope
              </label>
              <select
                value={portRange}
                onChange={(e) => setPortRange(e.target.value)}
                className="w-full h-9 px-2.5 rounded-md bg-[#0b1322] border border-slate-700 text-xs text-slate-200"
              >
                <option value="web">Standard Web Ports (80, 443, 8443)</option>
                <option value="top100">Top 100 Enterprise Ports</option>
                <option value="custom">Full Service Profile</option>
              </select>
            </div>

            <div className="grid grid-cols-2 gap-1.5 text-[11px] text-slate-400 pt-1">
              <div className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3 h-3 text-emerald-400 flex-shrink-0" />
                <span>TCP Port Probe</span>
              </div>
              <div className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3 h-3 text-emerald-400 flex-shrink-0" />
                <span>HTTP Headers</span>
              </div>
              <div className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3 h-3 text-emerald-400 flex-shrink-0" />
                <span>SSL/TLS Chain</span>
              </div>
              <div className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3 h-3 text-emerald-400 flex-shrink-0" />
                <span>Cloud AI Patch</span>
              </div>
            </div>
          </div>

          {/* Optional Auth Header */}
          <div>
            <label className="block text-[11px] text-slate-400 mb-1">
              Optional Authorization Header
            </label>
            <input
              type="text"
              value={authHeader}
              onChange={(e) => setAuthHeader(e.target.value)}
              placeholder="Bearer <token> (optional)"
              className="w-full h-9 px-3 rounded-lg bg-[#050a14] border border-slate-700 text-xs font-mono text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-[#0284c7]"
            />
          </div>

          {/* Primary Action Button */}
          <Button
            type="submit"
            className="w-full h-10 bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs font-bold uppercase tracking-wider shadow-md flex items-center justify-center gap-2"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            Initiate CyberDNA Scan
          </Button>

          {/* Footer Telemetry Status */}
          <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[11px] text-slate-400 font-mono">
            <span className="inline-flex items-center gap-1">
              <Database className="w-3 h-3 text-cyan-400" /> Audit Log
            </span>
            <span className="inline-flex items-center gap-1 text-emerald-400">
              <Activity className="w-3 h-3" /> Real-time
            </span>
            <span>REST API</span>
          </div>
        </form>
      </CardContent>
    </Card>
  );
};

export default TargetSpecificationPanel;