import React, { useState } from "react";
import { Sparkles, Loader2, ShieldCheck, Copy, Check } from "lucide-react";

interface AiFixPanelProps {
  title: string;
  description: string;
}

export const AiFixPanel: React.FC<AiFixPanelProps> = ({ title, description }) => {
  const [remediation, setRemediation] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  const handleGenerateFix = async (e: React.MouseEvent) => {
    e.stopPropagation();
    setLoading(true);
    setError(null);

    try {
      const response = await fetch("https://ai-vpan-backend.onrender.com/api/ai-fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title, description }),
      });

      const data = await response.json();

      if (!response.ok || data.error) {
        throw new Error(data.error || data.message || "Failed to generate AI fix.");
      }

      setRemediation(data.remediation);
    } catch (err: any) {
      setError(err.message || "Unable to connect to AI backend.");
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!remediation) return;
    navigator.clipboard.writeText(remediation);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      onClick={(e) => e.stopPropagation()}
      className="mt-4 pt-3 border-t border-slate-800/80"
    >
      {!remediation && (
        <button
          type="button"
          onClick={handleGenerateFix}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 transition-all disabled:opacity-50"
        >
          {loading ? (
            <>
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              Analyzing & Generating Patch...
            </>
          ) : (
            <>
              <Sparkles className="w-3.5 h-3.5" />
              Generate AI Fix
            </>
          )}
        </button>
      )}

      {error && (
        <p className="mt-2 text-xs text-red-400 bg-red-950/40 border border-red-800/50 rounded p-2">
          {error}
        </p>
      )}

      {remediation && (
        <div className="mt-2 rounded-lg bg-slate-950/90 border border-emerald-500/30 p-4">
          <div className="flex items-center justify-between mb-2 pb-2 border-b border-slate-800">
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
              <ShieldCheck className="w-4 h-4" />
              AI Security Remediation & Patch
            </span>
            <button
              type="button"
              onClick={handleCopy}
              className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-white transition-colors"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  Copied
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  Copy Patch
                </>
              )}
            </button>
          </div>
          <pre className="whitespace-pre-wrap font-mono text-xs text-slate-200 leading-relaxed overflow-x-auto">
            {remediation}
          </pre>
        </div>
      )}
    </div>
  );
};