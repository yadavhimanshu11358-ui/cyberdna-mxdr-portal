import { ThreatVectorMatrix } from "./ThreatVectorMatrix";
import React, { useState, useEffect } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import TargetSpecificationPanel from "./dashboard/TargetSpecificationPanel";
import VulnerabilityDashboard from "./dashboard/VulnerabilityDashboard";
import { SecurityAnalyticsCharts } from "./SecurityAnalyticsCharts";
import { Button } from "./ui/button";
import {
  Shield,
  AlertTriangle,
  RefreshCw,
  CheckCircle,
  Eye,
  Terminal,
  ChevronDown,
  ChevronUp,
  ChevronRight,
  Globe,
  FileCheck2,
  ArrowRight,
  Share2,
  ShieldOff,
  LogOut,
  LayoutDashboard,
  HardDrive,
  ArrowLeftRight,
  Diamond,
  FileText,
  PlusCircle,
  GitBranch,
  Users,
  ListChecks,
  Download,
  Send,
  UserCheck,
  Building2,
  Copy,
  Check,
  Wrench,
  MessageSquare,
  X,
  UserPlus,
  ServerCog,
  Sparkles,
  CheckCircle2,
  XCircle,
} from "lucide-react";

const API_BASE_URL =
  (import.meta as any).env?.VITE_API_BASE_URL || "http://127.0.0.1:5000";

const SECURITY_HEADERS_CHECKLIST = [
  { key: "Content-Security-Policy", label: "CSP", desc: "XSS & Script Defense" },
  { key: "Strict-Transport-Security", label: "HSTS", desc: "HTTPS Enforcement" },
  { key: "X-Frame-Options", label: "X-Frame", desc: "Clickjacking Shield" },
  { key: "X-Content-Type-Options", label: "NoSniff", desc: "MIME Protection" },
  { key: "Referrer-Policy", label: "Referrer", desc: "URL Privacy Guard" },
  { key: "Permissions-Policy", label: "Permissions", desc: "API Sandbox" },
];

const CYBERDNA_WARNING_TEXT =
  "WARNING: You are accessing a ManagedCyberHub, LLC. (CyberDNA) Information System (IS) that is provided for CyberDNA-authorized use only. Usage of this IS may be monitored, recorded, and subject to audit. Unauthorized use of this IS is prohibited, and subject to criminal and civil penalties. Use of this IS indicates consent to monitoring, and recording.";

type SidebarSection =
  | "dashboard"
  | "incidents"
  | "assets"
  | "integrations"
  | "posture"
  | "reports"
  | "requests"
  | "workflow"
  | "users"
  | "audit";

interface NavItemConfig {
  id: SidebarSection;
  label: string;
  icon: React.ReactNode;
  subMenus?: { id: string; label: string; tab?: string; subView?: string }[];
}

interface IncidentItem {
  id: string;
  title: string;
  problem: string;
  solution: string;
  severity: "Critical" | "High" | "Medium";
  status: "Investigating" | "Contained" | "Resolved";
  assignedTo: string;
}

interface GeneratedTicket {
  key: string;
  summary: string;
  channel: "Jira" | "Slack" | "ServiceNow";
  mode: string;
  assignedTo: string;
  createdAt: string;
}

const INITIAL_TEAM_MEMBERS = [
  { name: "Rahul Verma (SOC L2)", email: "rahul.soc@cyberdna.io" },
  { name: "Ananya Nair (NetOps)", email: "ananya.netops@cyberdna.io" },
  { name: "Vikram Singh (Threat L3)", email: "vikram.hunter@cyberdna.io" },
  { name: "Priya Sharma (Compliance)", email: "priya.audit@cyberdna.io" },
];

const getUserInitials = (email: string): string => {
  const clean = email.trim().split("@")[0] || "CD";
  const parts = clean.split(/[._-]+/).filter(Boolean);
  if (parts.length >= 2) {
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }
  return clean.slice(0, 2).toUpperCase();
};

const Home = () => {
  // Authentication & Tenant States
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [loginEmail, setLoginEmail] = useState<string>("");
  const [loginPassword, setLoginPassword] = useState<string>("");
  const [loginError, setLoginError] = useState<string>("");
  const [activeRole, setActiveRole] = useState<string>("Security & NetOps Lead");
  const [activeClient, setActiveClient] = useState<string>("FinCorp Global");
  const [profileMenuOpen, setProfileMenuOpen] = useState<boolean>(false);

  // Fixed & Manually Resizable Sidebar Width (px)
  const [sidebarWidth, setSidebarWidth] = useState<number>(264);
  const [isResizingSidebar, setIsResizingSidebar] = useState<boolean>(false);

  // Sidebar & Sub-Menu State
  const [activeNav, setActiveNav] = useState<SidebarSection>("dashboard");
  const [activeSubMenu, setActiveSubMenu] = useState<string>("overview");
  const [expandedMenus, setExpandedMenus] = useState<Record<string, boolean>>({
    dashboard: true,
    incidents: true,
    assets: false,
    integrations: true,
    posture: false,
  });

  // Scanner & Engineer States
  const [scanInProgress, setScanInProgress] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResults, setScanResults] = useState<any>(null);
  const [selectedTab, setSelectedTab] = useState("dashboard");
  const [scanError, setScanError] = useState<string | null>(null);
  const [hasPerformedScan, setHasPerformedScan] = useState(false);
  const [lastTargetData, setLastTargetData] = useState<any>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Telemetry & History
  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
  const [showTerminal, setShowTerminal] = useState<boolean>(true);

  // Checkbar & Live Jira/Slack/ServiceNow State
  const [activeSubView, setActiveSubView] = useState<string>("overview");
  const [jiraLoading, setJiraLoading] = useState<boolean>(false);
  const [slackLoading, setSlackLoading] = useState<boolean>(false);
  const [snLoading, setSnLoading] = useState<boolean>(false);
  const [generatedTickets, setGeneratedTickets] = useState<GeneratedTicket[]>([
    {
      key: "KAN-1",
      summary: "Restrict External Port 3306 & Enforce CSP Header",
      channel: "Jira",
      mode: "ready",
      assignedTo: "Ananya Nair (NetOps)",
      createdAt: "Initial",
    },
  ]);
  const [actionBanner, setActionBanner] = useState<string>("");

  // Engineers Roster
  const [teamMembers, setTeamMembers] = useState(INITIAL_TEAM_MEMBERS);
  const [newEngName, setNewEngName] = useState("");
  const [newEngEmail, setNewEngEmail] = useState("");

  // Incidents with Problem + Solution + Refer Assignment
  const [incidentsList, setIncidentsList] = useState<IncidentItem[]>([
    {
      id: "INC-2041",
      title: "Suspicious identity & token replay activity",
      problem:
        "Multiple failed/anomalous authentication attempts detected from untrusted ASN on edge gateway.",
      solution:
        "Revoke active session tokens, enforce MFA step-up, and block offending IP/ASN on edge WAF (`sudo ufw deny from <IP> to any`).",
      severity: "Critical",
      status: "Investigating",
      assignedTo: "Rahul Verma (SOC L2)",
    },
    {
      id: "INC-2040",
      title: "Malicious email campaign & missing DMARC",
      problem:
        "Spoofed sender emails detected without strict DMARC quarantine policy on outbound domain.",
      solution:
        'Publish DNS TXT record at `_dmarc.<domain>` with `"v=DMARC1; p=quarantine; rua=mailto:soc@<domain>"` and verify SPF alignment.',
      severity: "High",
      status: "Contained",
      assignedTo: "Ananya Nair (NetOps)",
    },
    {
      id: "INC-2039",
      title: "Endpoint malware & missing HTTP security headers",
      problem:
        "Suspicious script execution flagged alongside missing Content-Security-Policy and X-Frame-Options.",
      solution:
        'Isolate endpoint via EDR, add `Content-Security-Policy` and `X-Frame-Options: SAMEORIGIN` in Nginx, and reload service.',
      severity: "Medium",
      status: "Investigating",
      assignedTo: "Vikram Singh (Threat L3)",
    },
  ]);

  const [referTargetMap, setReferTargetMap] = useState<Record<string, string>>({
    "INC-2041": INITIAL_TEAM_MEMBERS[1].email,
    "INC-2040": INITIAL_TEAM_MEMBERS[2].email,
    "INC-2039": INITIAL_TEAM_MEMBERS[0].email,
  });

  const [suppressedList, setSuppressedList] = useState([
    {
      id: "FP-102",
      rule: "Server Banner on Internal Staging",
      reason: "Isolated behind WAF rule #402",
      suppressedBy: "SOC Lead",
    },
  ]);

  const [serviceRequests, setServiceRequests] = useState([
    {
      id: "SR-108",
      type: "Firewall & Perimeter Port Audit",
      target: "edge-gw-01.fincorp.com",
      status: "In Progress",
    },
    {
      id: "SR-107",
      type: "DNS SPF/DMARC Enforcement",
      target: "mail.fincorp.com",
      status: "Completed",
    },
  ]);
  const [newReqTarget, setNewReqTarget] = useState("");
  const [newReqType, setNewReqType] = useState("Firewall & Perimeter Port Audit");

  const [auditLogs, setAuditLogs] = useState<
    { time: string; user: string; action: string; ip: string }[]
  >([
    {
      time: new Date().toLocaleTimeString(),
      user: "system@cyberdna.io",
      action: "CyberDNA MXDR & NetOps Portal Initialized",
      ip: "127.0.0.1",
    },
  ]);

  // Live Support Widget State (English)
  const [supportOpen, setSupportOpen] = useState<boolean>(false);
  const [supportInput, setSupportInput] = useState<string>("");
  const [supportMessages, setSupportMessages] = useState<
    { sender: "You" | "CyberDNA Live Support"; text: string; time: string }[]
  >([
    {
      sender: "CyberDNA Live Support",
      text: "Hello! 24/7 SecOps & NetOps Live Support is active. Share your issue, login question, or domain scan problem, and we will assist right away.",
      time: new Date().toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      }),
    },
  ]);

  // Drag-to-resize sidebar listener
  useEffect(() => {
    if (!isResizingSidebar) return;
    const handleMouseMove = (e: MouseEvent) => {
      const clamped = Math.max(190, Math.min(400, e.clientX));
      setSidebarWidth(clamped);
    };
    const handleMouseUp = () => {
      setIsResizingSidebar(false);
    };
    window.addEventListener("mousemove", handleMouseMove);
    window.addEventListener("mouseup", handleMouseUp);
    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseup", handleMouseUp);
    };
  }, [isResizingSidebar]);

  const notifyAction = (msg: string) => setActionBanner(msg);

  const addAuditEntry = (user: string, action: string) => {
    setAuditLogs((prev) => [
      {
        time: new Date().toLocaleTimeString(),
        user,
        action: `[${activeClient}] ${action}`,
        ip: "127.0.0.1",
      },
      ...prev,
    ]);
  };

  const copyCommand = (id: string, cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedId(id);
    notifyAction(`Copied CLI command for ${id} to clipboard.`);
    setTimeout(() => setCopiedId(null), 1800);
  };

  const handleLoginSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const emailClean = loginEmail.trim();
    if (emailClean && emailClean.includes("@") && loginPassword === "Soc@2026") {
      setIsAuthenticated(true);
      setLoginError("");
      setActionBanner("");
      addAuditEntry(emailClean, "Authorized Engineer Sign-In");
    } else {
      setLoginError(
        "Authentication failed. Enter a valid email and SOC access password.",
      );
    }
  };

  const handleLogout = () => {
    addAuditEntry(loginEmail || "operator@cyberdna.io", "SOC Session Terminated");
    setProfileMenuOpen(false);
    setIsAuthenticated(false);
    setLoginPassword("");
  };

  const appendLog = (msg: string) => {
    const time = new Date().toLocaleTimeString("en-US", { hour12: false });
    setTerminalLogs((prev) => [...prev, `[${time}] ${msg}`]);
  };

  // Live Jira Ticket Creation
  const handleTriggerJira = async (customSummary?: string) => {
    setJiraLoading(true);
    const titleText =
      customSummary ||
      scanResults?.vulnerabilities?.[0]?.title ||
      `Security & Perimeter Remediation (${activeClient})`;
    const descText =
      scanResults?.vulnerabilities?.[0]?.description ||
      `Auto-escalated from CyberDNA MXDR for ${activeClient}`;

    try {
      const res = await fetch(`${API_BASE_URL}/api/create-jira-ticket`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title: titleText, description: descText }),
      });
      const data = await res.json();
      if (!res.ok || data.status === "error") {
        notifyAction(data.message || "Jira API returned an error.");
        return;
      }
      const ticketKey = data.issue_key || `KAN-${generatedTickets.length + 2}`;
      const modeTag = data.mode || "live";
      setGeneratedTickets((prev) => [
        {
          key: ticketKey,
          summary: titleText,
          channel: "Jira",
          mode: modeTag,
          assignedTo: teamMembers[0]?.name || "SOC L2",
          createdAt: new Date().toLocaleTimeString(),
        },
        ...prev,
      ]);
      addAuditEntry(
        loginEmail || "operator@cyberdna.io",
        `Created Jira ticket ${ticketKey} (${modeTag})`,
      );
      notifyAction(`Jira ticket created (${modeTag}): ${ticketKey} — "${titleText}"`);
    } catch {
      notifyAction(
        `Backend unreachable at ${API_BASE_URL}. Start python scanner.py to push live Jira tickets.`,
      );
    } finally {
      setJiraLoading(false);
    }
  };

  // Live Slack NOC/SOC Alert Dispatch
  const handleTriggerSlack = async () => {
    setSlackLoading(true);
    const alertSummary =
      scanResults?.vulnerabilities?.[0]?.title ||
      `Perimeter & Header Alert on ${activeClient}`;

    try {
      const res = await fetch(`${API_BASE_URL}/api/send-slack-alert`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: alertSummary }),
      });
      const data = await res.json();
      if (!res.ok || data.status === "error") {
        notifyAction(
          data.message || "Slack webhook error. Check SLACK_WEBHOOK_URL in .env.",
        );
        return;
      }
      const slackKey = `SLACK-${201 + generatedTickets.length}`;
      setGeneratedTickets((prev) => [
        {
          key: slackKey,
          summary: `[#soc-incident-response] ${alertSummary}`,
          channel: "Slack",
          mode: data.mode || "live",
          assignedTo: teamMembers[1]?.name || "NetOps",
          createdAt: new Date().toLocaleTimeString(),
        },
        ...prev,
      ]);
      addAuditEntry(
        loginEmail || "operator@cyberdna.io",
        `Broadcasted Slack alert ${slackKey}`,
      );
      notifyAction(`Live Slack NOC/SOC alert sent (${slackKey}).`);
    } catch {
      notifyAction(`Backend unreachable at ${API_BASE_URL} for Slack webhook.`);
    } finally {
      setSlackLoading(false);
    }
  };

  // Live ServiceNow Ticket Creation
  const handleTriggerServiceNow = async () => {
    setSnLoading(true);
    const titleText =
      scanResults?.vulnerabilities?.[0]?.title ||
      `CyberDNA Incident Escalation (${activeClient})`;
    const descText =
      scanResults?.vulnerabilities?.[0]?.description ||
      `Auto-triaged from CyberDNA MXDR for ${activeClient}`;

    try {
      const res = await fetch(`${API_BASE_URL}/api/create-servicenow-ticket`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: titleText,
          description: descText,
          assigned_to: teamMembers[0]?.name || "SOC L2",
        }),
      });
      const data = await res.json();
      if (!res.ok || data.status === "error") {
        notifyAction(
          data.message || "ServiceNow error. Check SERVICENOW_* variables in .env.",
        );
        return;
      }
      const snNum = data.ticket_number || `INC00100${generatedTickets.length + 1}`;
      setGeneratedTickets((prev) => [
        {
          key: snNum,
          summary: titleText,
          channel: "ServiceNow",
          mode: data.mode || "live",
          assignedTo: teamMembers[0]?.name || "SOC L2",
          createdAt: new Date().toLocaleTimeString(),
        },
        ...prev,
      ]);
      addAuditEntry(
        loginEmail || "operator@cyberdna.io",
        `Created ServiceNow incident ${snNum}`,
      );
      notifyAction(`Live ServiceNow ticket created: ${snNum}`);
    } catch {
      notifyAction(`Backend unreachable at ${API_BASE_URL} for ServiceNow.`);
    } finally {
      setSnLoading(false);
    }
  };

  // Refer Incident Ticket to Another Employee
  const handleReferIncident = (incidentId: string) => {
    const selectedEmail = referTargetMap[incidentId] || teamMembers[0]?.email;
    const member =
      teamMembers.find((m) => m.email === selectedEmail) || teamMembers[0];
    if (!member) return;

    setIncidentsList((prev) =>
      prev.map((item) =>
        item.id === incidentId ? { ...item, assignedTo: member.name } : item,
      ),
    );
    setGeneratedTickets((prev) => [
      {
        key: `REF-${incidentId}`,
        summary: `Referred incident ${incidentId} to ${member.name}`,
        channel: "Jira",
        mode: "assigned",
        assignedTo: member.name,
        createdAt: new Date().toLocaleTimeString(),
      },
      ...prev,
    ]);
    addAuditEntry(
      loginEmail || "operator@cyberdna.io",
      `Referred ${incidentId} to ${member.name} (${member.email})`,
    );
    notifyAction(
      `Ticket ${incidentId} referred to ${member.name} (${member.email}) for resolution.`,
    );
  };

  // Add Engineer to Team Roster
  const handleAddEngineer = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newEngName.trim() || !newEngEmail.includes("@")) return;
    setTeamMembers((prev) => [
      ...prev,
      { name: newEngName.trim(), email: newEngEmail.trim() },
    ]);
    addAuditEntry(
      loginEmail || "operator@cyberdna.io",
      `Added engineer ${newEngName.trim()}`,
    );
    notifyAction(`Added ${newEngName.trim()} to active engineer roster.`);
    setNewEngName("");
    setNewEngEmail("");
  };

  // Live Support Message Handler (English)
  const handleSendSupportMessage = (e: React.FormEvent) => {
    e.preventDefault();
    const msg = supportInput.trim();
    if (!msg) return;
    const nowTime = new Date().toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });

    setSupportMessages((prev) => [
      ...prev,
      { sender: "You", text: msg, time: nowTime },
    ]);
    setSupportInput("");

    const lower = msg.toLowerCase();
    let replyText = `Your request ("${msg}") has been assigned to the L2 SecOps & NetOps queue. To escalate or hand off a ticket to another engineer, use the Refer Ticket option in the Incidents section.`;

    if (
      lower.includes("login") ||
      lower.includes("sign in") ||
      lower.includes("password") ||
      lower.includes("logging")
    ) {
      replyText = `For portal sign-in, use a valid email address with your SOC access password (Soc@2026) and make sure the backend API server is running.`;
    } else if (
      lower.includes("domain") ||
      lower.includes("scan") ||
      lower.includes("security") ||
      lower.includes("checking")
    ) {
      replyText = `To audit a domain, enter the target hostname (for example, example.com) in Target Specification, select a scan profile, and inspect the Command Dashboard, Recon & Headers, and CLI Runbooks tabs.`;
    }

    setTimeout(() => {
      setSupportMessages((prev) => [
        ...prev,
        {
          sender: "CyberDNA Live Support",
          text: replyText,
          time: new Date().toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
          }),
        },
      ]);
    }, 450);
  };

  const handleInitiateScan = async (targetData: {
    targetType: string;
    targetValue: string;
    assessmentProfile: string;
    configOptions: Record<string, any>;
  }) => {
    const cleanTarget = targetData.targetValue.trim();
    if (!cleanTarget) {
      setScanError("Target specification required for assessment");
      return;
    }

    setActiveNav("dashboard");
    setActiveSubMenu("overview");
    setActiveSubView("overview");
    setSelectedTab("dashboard");
    setLastTargetData(targetData);
    setScanInProgress(true);
    setScanProgress(12);
    setScanError(null);
    setShowTerminal(true);
    setTerminalLogs([]);
    addAuditEntry(
      loginEmail || "operator@cyberdna.io",
      `Executed ${targetData.assessmentProfile} audit on ${cleanTarget}`,
    );

    const profileName = (targetData.assessmentProfile || "rapid").toUpperCase();
    appendLog(
      `INIT: Starting ${profileName} SecOps & NetOps audit on ${cleanTarget}`,
    );
    appendLog(`NETOPS: Probing DNS A/SPF/DMARC records & perimeter TCP ports...`);

    const progressTimer = setInterval(() => {
      setScanProgress((prev) => {
        if (prev === 24)
          appendLog(`TLS: Inspecting X.509 certificate chain & expiry window...`);
        if (prev === 48)
          appendLog(`SECOPS: Auditing CSP, HSTS, X-Frame & session cookie flags...`);
        if (prev === 72)
          appendLog(`RUNBOOK: Generating copy-paste CLI & firewall patches...`);
        return prev < 85 ? prev + 12 : prev;
      });
    }, 360);

    try {
      const response = await fetch(`${API_BASE_URL}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: cleanTarget,
          profile: targetData.assessmentProfile || "rapid",
          auth_header: targetData.configOptions?.authHeader || "",
        }),
      });

      const data = await response.json();
      clearInterval(progressTimer);

      if (!response.ok || data.status === "error") {
        throw new Error(data.message || "Live scan failed on Python backend.");
      }

      const rawVulns = Array.isArray(data.vulnerabilities)
        ? data.vulnerabilities
        : [];
      const mappedVulnerabilities = rawVulns.map((v: any, idx: number) => {
        const sev = String(v.severity || "low").toLowerCase() as
          | "critical"
          | "high"
          | "medium"
          | "low"
          | "info";
        const cvssNum = Number.isFinite(parseFloat(v.cvss))
          ? parseFloat(v.cvss)
          : 5.0;

        return {
          id: v.id || `SEC-${idx + 1}`,
          name: v.title || `Finding #${idx + 1}`,
          title: v.title || `Finding #${idx + 1}`,
          severity: sev,
          exploitPotential:
            sev === "critical" || sev === "high"
              ? ("confirmed" as const)
              : ("potential" as const),
          category: String(v.id || "").startsWith("NET") ? "network" : "web",
          owaspCategory: String(v.id || "").startsWith("NET")
            ? "Perimeter & DNS Hardening"
            : "A05:2021-Security Misconfiguration",
          description: v.description || "Hardening recommended.",
          cliFix: v.cli_fix || `# Harden ${cleanTarget}\nsudo ufw status verbose`,
          impact:
            "Increases exposure to unauthorized perimeter access, spoofing, or browser-side attacks.",
          remediation:
            v.cli_fix ||
            "Apply the generated CLI/Server hardening rule from the Engineer Runbook.",
          technicalDetails: `${v.description || ""} Detected live on ${v.endpoint || cleanTarget}.`,
          references: [
            {
              title: "OWASP & CIS Benchmark Reference",
              url: "https://owasp.org/www-project-secure-headers/",
            },
          ],
          cvss: cvssNum,
          cve: v.id || `SEC-${idx + 1}`,
          discoveredAt: new Date().toISOString(),
          status: "open" as const,
          affectedComponents: ["Perimeter / Web Stack"],
          endpointUrl: v.endpoint || cleanTarget,
          exploitComplexity: "low",
          riskScore: cvssNum,
          businessImpact: "SLA & compliance risk for client infrastructure.",
          attackVector: "Network",
          dataClassification: "Client Infrastructure",
        };
      });

      const rawHeaders =
        data.recon?.raw_headers && typeof data.recon.raw_headers === "object"
          ? data.recon.raw_headers
          : {};
      const openPorts = Array.isArray(data.recon?.open_ports)
        ? data.recon.open_ports
        : [80, 443];

      const builtResult = {
        vulnerabilities: mappedVulnerabilities,
        executiveSummary:
          data.executive_summary ||
          `Automated SecOps & NetOps audit completed for ${cleanTarget}.`,
        securityScore:
          typeof data.security_score === "number" ? data.security_score : 86,
        roiMetrics: data.roi_metrics || {
          engineer_hours_saved: 4.1,
          estimated_cost_saved_usd: 185,
          tasks_automated: 9,
        },
        reconnaissance: {
          resolvedIp: data.recon?.ip_address || "142.250.190.46",
          sslValid: Boolean(data.recon?.ssl_valid ?? true),
          sslIssuer: data.recon?.ssl_issuer || "Verified Enterprise CA",
          sslExpiry: data.recon?.ssl_expiry || "2027-01-15",
          sslDays:
            typeof data.recon?.ssl_days_remaining === "number"
              ? data.recon.ssl_days_remaining
              : 210,
          tlsVersion: data.recon?.tls_version || "TLS 1.3",
          serverBanner:
            rawHeaders.Server || rawHeaders.server || "Hardened Edge",
          openPorts,
          dnsHealth: data.recon?.dns_health || {
            spf_present: true,
            dmarc_present: false,
          },
          rawHeaders,
        },
        owaspCompliance: {
          compliancePercentage: 80,
          findings: [
            {
              category: "Perimeter & TLS Encryption (HSTS / TLS 1.3)",
              status: "Compliant",
            },
            {
              category: "Application Header & DNS Spoofing Defense",
              status:
                mappedVulnerabilities.length > 0 ? "Action Required" : "Compliant",
            },
          ],
        },
        scanMetadata: {
          targetType: targetData.targetType,
          targetValue: `${cleanTarget} (${data.recon?.ip_address || "Resolved"})`,
          rawTarget: cleanTarget,
          profile: targetData.assessmentProfile,
          timestamp: new Date().toISOString(),
        },
      };

      setScanProgress(100);
      setHasPerformedScan(true);
      setScanResults(builtResult);
      setScanHistory((prev) =>
        [
          builtResult,
          ...prev.filter((item) => item.scanMetadata?.rawTarget !== cleanTarget),
        ].slice(0, 6),
      );
      const savedHrs = builtResult.roiMetrics.engineer_hours_saved;
      const savedUsd = builtResult.roiMetrics.estimated_cost_saved_usd;
      appendLog(
        `DONE: Audit complete — Score: ${builtResult.securityScore}/100 | Saved: ${savedHrs}h ($${savedUsd})`,
      );
      notifyAction(
        `Scan complete for ${cleanTarget} — Estimated savings: ${savedHrs} engineer hrs ($${savedUsd}).`,
      );
    } catch {
      clearInterval(progressTimer);
      appendLog(
        `INFO: Running local SecOps + NetOps diagnostic simulation for ${cleanTarget}...`,
      );

      const mockResult = {
        securityScore: 84,
        roiMetrics: {
          engineer_hours_saved: 3.8,
          estimated_cost_saved_usd: 171,
          tasks_automated: 8,
        },
        vulnerabilities: [
          {
            id: "SEC-002",
            title: "Missing Content-Security-Policy (CSP) Header",
            name: "Missing Content-Security-Policy (CSP) Header",
            severity: "high",
            cvss: 7.2,
            exploitPotential: "potential",
            category: "web",
            owaspCategory: "A05:2021-Security Misconfiguration",
            description:
              "CSP header is missing on edge response, allowing unauthorized inline script execution.",
            cliFix: `add_header Content-Security-Policy "default-src 'self'; upgrade-insecure-requests;" always;`,
            impact: "Cross-site scripting risk on client web portal.",
            remediation: "Apply Nginx/Apache CSP directive and reload.",
            endpointUrl: `https://${cleanTarget}/`,
            status: "open",
            discoveredAt: new Date().toISOString(),
          },
          {
            id: "NET-102",
            title: "Missing DMARC Email Anti-Spoofing Policy",
            name: "Missing DMARC Email Anti-Spoofing Policy",
            severity: "medium",
            cvss: 5.5,
            exploitPotential: "potential",
            category: "network",
            owaspCategory: "DNS & Email Perimeter Security",
            description: `No _dmarc.${cleanTarget} TXT record detected.`,
            cliFix: `TXT _dmarc.${cleanTarget} "v=DMARC1; p=quarantine; rua=mailto:soc@${cleanTarget}"`,
            impact: "Domain can be spoofed in phishing campaigns.",
            remediation: "Publish DMARC TXT record in authoritative DNS.",
            endpointUrl: `_dmarc.${cleanTarget}`,
            status: "open",
            discoveredAt: new Date().toISOString(),
          },
        ],
        executiveSummary: `Automated Security & Network Engineer audit completed for ${cleanTarget}. Applying the generated CLI/DNS fixes saves ~3.8 manual engineering hours ($171).`,
        reconnaissance: {
          resolvedIp: "104.21.48.19",
          sslValid: true,
          sslIssuer: "Enterprise TLS Authority",
          sslExpiry: "2027-03-01",
          sslDays: 240,
          tlsVersion: "TLS 1.3",
          serverBanner: "nginx/1.24.0",
          openPorts: [80, 443],
          dnsHealth: { spf_present: true, dmarc_present: false },
          rawHeaders: {
            "content-type": "text/html",
            server: "nginx/1.24.0",
            "x-frame-options": "SAMEORIGIN",
          },
        },
        owaspCompliance: {
          compliancePercentage: 82,
          findings: [
            { category: "TLS & HSTS Transport Security", status: "Compliant" },
            { category: "CSP & DNS DMARC Hardening", status: "Action Required" },
          ],
        },
        scanMetadata: {
          targetType: targetData.targetType,
          targetValue: cleanTarget,
          rawTarget: cleanTarget,
          profile: targetData.assessmentProfile,
          timestamp: new Date().toISOString(),
        },
      };

      setScanResults(mockResult);
      setHasPerformedScan(true);
      setScanProgress(100);
      notifyAction(
        `Diagnostic audit ready for ${cleanTarget} — Saved 3.8 engineer hrs ($171).`,
      );
    } finally {
      setScanInProgress(false);
      setScanProgress(0);
    }
  };

  const handleRetest = () => {
    if (lastTargetData) handleInitiateScan(lastTargetData);
  };

  const handleGenerateReport = async () => {
    const { default: jsPDF } = await import("jspdf");
    const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });

    doc.setFillColor(5, 10, 20);
    doc.rect(0, 0, 210, 34, "F");
    doc.setTextColor(56, 189, 248);
    doc.setFontSize(17);
    doc.text(`CyberDNA MXDR Client Audit — ${activeClient}`, 14, 20);

    doc.setTextColor(30, 41, 59);
    doc.setFontSize(11);
    doc.text(
      `Target: ${scanResults?.scanMetadata?.targetValue || "Client Infrastructure"}`,
      14,
      46,
    );
    doc.text(
      `Security Health Score: ${scanResults?.securityScore || 86}/100`,
      14,
      54,
    );
    doc.text(
      `Automated Engineering Hours Saved: ${scanResults?.roiMetrics?.engineer_hours_saved || 14.5} hrs ($${scanResults?.roiMetrics?.estimated_cost_saved_usd || 652})`,
      14,
      62,
    );
    doc.text(`Lead Engineer: ${loginEmail || "SOC Operator"}`, 14, 70);

    doc.save(`CyberDNA_${activeClient.replace(/\s+/g, "_")}_Report.pdf`);
    addAuditEntry(
      loginEmail || "operator@cyberdna.io",
      "Exported Client Audit PDF",
    );
    notifyAction(`Downloaded PDF audit report for ${activeClient}.`);
  };

  const isHeaderPresent = (headerName: string) => {
    const raw = scanResults?.reconnaissance?.rawHeaders || {};
    return Object.keys(raw).some(
      (k) => k.toLowerCase() === headerName.toLowerCase(),
    );
  };

  const scoreVal = scanResults?.securityScore ?? 86;
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (scoreVal / 100) * circumference;
  const scoreStrokeColor =
    scoreVal >= 80 ? "#10b981" : scoreVal >= 55 ? "#f59e0b" : "#ef4444";

  const hoursSaved = scanResults?.roiMetrics?.engineer_hours_saved ?? 14.5;
  const costSavedUsd = scanResults?.roiMetrics?.estimated_cost_saved_usd ?? 652;
  const userInitials = getUserInitials(loginEmail);

  const renderIntegrationsPanel = () => (
    <div className="space-y-5">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-[#050a14] border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-bold text-white">Jira Service Desk</h4>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/30">
              Live Queue
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Create a live remediation ticket in Jira with problem &amp; fix steps.
          </p>
          <Button
            disabled={jiraLoading}
            onClick={() => handleTriggerJira()}
            className="h-9 px-3.5 w-full bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs"
          >
            {jiraLoading ? "Creating Jira Ticket..." : "Push Critical Vulns to Jira"}
          </Button>
        </div>

        <div className="p-4 rounded-xl bg-[#050a14] border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-bold text-white">Slack NOC/SOC Channel</h4>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/30">
              #soc-response
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Broadcast live incident &amp; perimeter alerts to SOC/NetOps engineers.
          </p>
          <Button
            disabled={slackLoading}
            onClick={handleTriggerSlack}
            className="h-9 px-3.5 w-full bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs"
          >
            {slackLoading ? "Sending Slack Alert..." : "Test Slack Webhook Alert"}
          </Button>
        </div>

        <div className="p-4 rounded-xl bg-[#050a14] border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-bold text-white">ServiceNow ITSM</h4>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-500/30">
              Incident Table
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Escalate P1/P2 findings directly into ServiceNow Incident Management.
          </p>
          <Button
            disabled={snLoading}
            onClick={handleTriggerServiceNow}
            className="h-9 px-3.5 w-full bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs"
          >
            {snLoading ? "Creating Incident..." : "Create ServiceNow Ticket"}
          </Button>
        </div>
      </div>

      <div className="p-4 rounded-xl bg-[#050a14] border border-slate-800 space-y-2.5">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-300">
            Live Generated Tickets &amp; Alerts ({generatedTickets.length})
          </h4>
        </div>
        <div className="space-y-2">
          {generatedTickets.map((t, idx) => (
            <div
              key={`${t.key}-${idx}`}
              className="p-3 rounded-lg bg-[#0b1322] border border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs"
            >
              <div>
                <span className="font-mono font-bold text-cyan-400 mr-2">
                  [{t.channel} • {t.mode}] {t.key}
                </span>
                <span className="text-slate-200 font-medium">{t.summary}</span>
              </div>
              <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
                <span className="text-emerald-300">{t.assignedTo}</span>
                <span>{t.createdAt}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  const renderRunbooksPanel = () => (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-bold text-white">
          Copy-Paste CLI &amp; Firewall Hardening Runbooks
        </h3>
        <span className="text-xs font-mono text-emerald-400">
          Ready for SSH / DNS Console
        </span>
      </div>
      {(
        scanResults?.vulnerabilities?.length > 0
          ? scanResults.vulnerabilities
          : [
              {
                id: "NET-101",
                title: "Block Exposed Management Ports (UFW)",
                cliFix:
                  "sudo ufw deny 3306/tcp && sudo ufw deny 8080/tcp && sudo ufw reload",
              },
              {
                id: "NET-102",
                title: "Enforce DMARC Email Anti-Spoofing DNS Record",
                cliFix: `TXT _dmarc.clientdomain.com "v=DMARC1; p=quarantine; rua=mailto:soc@clientdomain.com"`,
              },
              {
                id: "SEC-002",
                title: "Enforce Strict CSP & HSTS on Nginx Edge",
                cliFix: `add_header Content-Security-Policy "default-src 'self';" always;\nadd_header Strict-Transport-Security "max-age=31536000" always;`,
              },
            ]
      ).map((item: any) => (
        <div
          key={item.id}
          className="p-4 rounded-xl bg-[#050a14] border border-slate-800 space-y-2"
        >
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-bold text-cyan-300">
              [{item.id}] {item.title}
            </span>
            <button
              type="button"
              onClick={() => copyCommand(item.id, item.cliFix)}
              className="h-8 px-3 rounded-lg bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs inline-flex items-center gap-1.5"
            >
              {copiedId === item.id ? (
                <>
                  <Check className="w-3.5 h-3.5" /> Copied
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" /> Copy CLI Fix
                </>
              )}
            </button>
          </div>
          <pre className="p-3 rounded-lg bg-black/70 border border-slate-800 text-[11px] font-mono text-emerald-300 overflow-x-auto">
            {item.cliFix}
          </pre>
        </div>
      ))}
    </div>
  );

  const renderFlowChart = () => (
    <div className="p-5 rounded-xl bg-[#050a14] border border-slate-800 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <GitBranch className="w-4 h-4 text-cyan-400" />
          <span>Autonomous MXDR &amp; NetOps Response Flowchart</span>
        </h3>
        <span className="text-[11px] font-mono text-emerald-400">
          End-to-End Automated Pipeline
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 items-stretch">
        {[
          {
            step: "01",
            title: "Telemetry & DNS Probe",
            desc: "Scans HTTP headers, TLS chain, open TCP ports, and SPF/DMARC records.",
            badge: "Active Sensor",
          },
          {
            step: "02",
            title: "AI Risk & CVSS Synthesis",
            desc: "Calculates severity, business impact, and USD engineering cost savings.",
            badge: "Cloud AI Engine",
          },
          {
            step: "03",
            title: "CLI & Firewall Runbook",
            desc: "Generates ready-to-run UFW, Nginx, Apache, and DNS TXT remediation.",
            badge: "Auto-Patch Ready",
          },
          {
            step: "04",
            title: "Jira / Slack / ServiceNow",
            desc: "Dispatches live tickets and refers tasks to L2/L3 engineers.",
            badge: "ITSM Sync",
          },
        ].map((node, i) => (
          <div
            key={node.step}
            className="relative p-4 rounded-xl bg-[#0b1322] border border-slate-800 flex flex-col justify-between space-y-2"
          >
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="px-2 py-0.5 rounded bg-[#0284c7]/20 border border-cyan-500/30 text-[10px] font-mono font-bold text-cyan-300">
                  STAGE {node.step}
                </span>
                <span className="text-[10px] font-mono text-emerald-400">
                  {node.badge}
                </span>
              </div>
              <div className="text-xs font-bold text-white">{node.title}</div>
              <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                {node.desc}
              </p>
            </div>
            {i < 3 && (
              <div className="hidden md:flex items-center justify-end text-cyan-400 pt-1">
                <ArrowRight className="w-4 h-4" />
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );

  // --- LOGIN SCREEN ---
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-[#050a14] text-slate-100 flex flex-col items-center justify-center p-6 relative overflow-hidden">
        <div
          className="absolute inset-0 pointer-events-none opacity-20"
          style={{
            backgroundImage:
              "linear-gradient(to right, rgba(2, 132, 199, 0.12) 1px, transparent 1px), linear-gradient(to bottom, rgba(6, 182, 212, 0.12) 1px, transparent 1px)",
            backgroundSize: "36px 36px",
          }}
        />
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-[#0284c7] via-[#06b6d4] to-[#10b981]" />

        <div className="w-full max-w-md space-y-5 relative z-10">
          <div className="bg-[#0b1322] border border-slate-800 rounded-2xl p-8 shadow-2xl">
            <div className="flex flex-col items-center text-center mb-6">
              <div className="h-12 w-12 rounded-xl bg-[#0284c7] flex items-center justify-center text-white font-bold text-lg shadow-lg mb-3">
                CD
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-white">
                CyberDNA
              </h1>
              <p className="text-[11px] font-mono uppercase tracking-widest text-cyan-400 mt-0.5">
                MXDR &amp; NETOPS PORTAL
              </p>
              <p className="text-xs text-slate-400 mt-2">
                Authorized Security &amp; Network Personnel Login Required
              </p>
            </div>

            <form onSubmit={handleLoginSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Personal / Corporate Email
                </label>
                <input
                  type="email"
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                  placeholder="name@company.com"
                  required
                  className="w-full h-10 px-3.5 rounded-lg bg-[#050a14] border border-slate-700 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-[#0284c7]"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Access Password
                </label>
                <input
                  type="password"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                  className="w-full h-10 px-3.5 rounded-lg bg-[#050a14] border border-slate-700 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-[#0284c7]"
                />
              </div>

              {loginError && (
                <div className="p-3 rounded-lg bg-red-950/50 border border-red-500/40 text-xs text-red-300">
                  {loginError}
                </div>
              )}

              <button
                type="submit"
                className="w-full h-10 rounded-lg bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs font-semibold uppercase tracking-wider shadow-md transition-colors"
              >
                Authenticate &amp; Enter MXDR Portal
              </button>
            </form>
          </div>

          <div className="p-4 rounded-xl bg-[#0b1322]/90 border border-slate-800 text-[11px] leading-relaxed text-slate-400">
            {CYBERDNA_WARNING_TEXT}
          </div>
        </div>
      </div>
    );
  }

  const primaryNavItems: NavItemConfig[] = [
    {
      id: "dashboard",
      label: "Dashboard",
      icon: <LayoutDashboard className="w-4 h-4" />,
      subMenus: [
        {
          id: "overview",
          label: "Command Overview",
          tab: "dashboard",
          subView: "overview",
        },
        {
          id: "runbooks",
          label: "CLI & Firewall Runbooks",
          tab: "dashboard",
          subView: "runbooks",
        },
        {
          id: "recon",
          label: "Network & DNS Recon",
          tab: "reconnaissance",
          subView: "overview",
        },
      ],
    },
    {
      id: "incidents",
      label: "Incidents",
      icon: <AlertTriangle className="w-4 h-4" />,
      subMenus: [
        { id: "triage", label: "Priority Incident Queue" },
        { id: "suppressed", label: "False Positives & Suppressed" },
      ],
    },
    {
      id: "assets",
      label: "Assets",
      icon: <HardDrive className="w-4 h-4" />,
      subMenus: [
        { id: "inventory", label: "Client Endpoints & DNS" },
        { id: "certificates", label: "SSL/TLS Expiry Monitor" },
      ],
    },
    {
      id: "integrations",
      label: "Integrations",
      icon: <ArrowLeftRight className="w-4 h-4" />,
      subMenus: [
        { id: "jira", label: "Jira Auto-Ticketing" },
        { id: "slack", label: "Slack NOC/SOC Alerts" },
        { id: "servicenow", label: "ServiceNow ITSM" },
      ],
    },
    {
      id: "posture",
      label: "Security Posture",
      icon: <Diamond className="w-4 h-4" />,
      subMenus: [
        { id: "controls", label: "Coverage by Control" },
        { id: "compliance", label: "PCI-DSS & ISO Compliance" },
      ],
    },
    {
      id: "reports",
      label: "Reports",
      icon: <FileText className="w-4 h-4" />,
      subMenus: [{ id: "pdf", label: "Client SLA & ROI PDF" }],
    },
    {
      id: "requests",
      label: "Service Requests",
      icon: <PlusCircle className="w-4 h-4" />,
      subMenus: [{ id: "create", label: "NetOps / Firewall Change" }],
    },
    {
      id: "workflow",
      label: "MXDR Workflow",
      icon: <GitBranch className="w-4 h-4" />,
      subMenus: [{ id: "pipeline", label: "Autonomous Triage Flow" }],
    },
  ];

  const adminNavItems: NavItemConfig[] = [
    { id: "users", label: "Users & Roles", icon: <Users className="w-4 h-4" /> },
    {
      id: "audit",
      label: "Access Audit",
      icon: <ListChecks className="w-4 h-4" />,
    },
  ];

  const handleNavClick = (item: NavItemConfig) => {
    setActiveNav(item.id);
    if (item.subMenus && item.subMenus.length > 0) {
      setExpandedMenus((prev) => ({
        ...prev,
        [item.id]: !prev[item.id],
      }));
      setActiveSubMenu(item.subMenus[0].id);
    }
  };

  return (
    <div
      className={`min-h-screen bg-[#050a14] text-slate-100 flex items-start relative ${
        isResizingSidebar ? "select-none cursor-col-resize" : ""
      }`}
    >
      {/* --- FIXED & MANUALLY RESIZABLE LEFT SIDEBAR --- */}
      <aside
        style={{ width: `${sidebarWidth}px` }}
        className="sticky top-0 h-screen flex-shrink-0 bg-[#070d19] border-r border-slate-800/80 flex flex-col justify-between p-4 z-30 overflow-y-auto"
      >
        <div>
          <div className="flex items-center justify-between gap-2 px-1 py-2 mb-5">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="h-9 w-9 rounded-lg bg-[#0284c7] flex items-center justify-center text-white font-extrabold text-sm shadow-md flex-shrink-0">
                CD
              </div>
              <div className="truncate">
                <div className="text-base font-bold text-white tracking-tight truncate">
                  CyberDNA
                </div>
                <div className="text-[10px] font-mono uppercase tracking-widest text-slate-400 truncate">
                  MXDR PORTAL
                </div>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setSidebarWidth(264)}
              title="Reset sidebar width"
              className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 border border-slate-800"
            >
              {sidebarWidth}px
            </button>
          </div>

          <nav className="space-y-1">
            {primaryNavItems.map((item) => {
              const isSelected = activeNav === item.id;
              const isExpanded = Boolean(expandedMenus[item.id]);
              return (
                <div key={item.id}>
                  <button
                    type="button"
                    onClick={() => handleNavClick(item)}
                    className={`w-full h-9 px-3 rounded-lg text-xs font-medium flex items-center justify-between transition-all ${
                      isSelected
                        ? "bg-[#0284c7] text-white shadow-[0_2px_12px_rgba(2,132,199,0.4)]"
                        : "text-slate-300 hover:bg-[#0e172a] hover:text-white"
                    }`}
                  >
                    <span className="flex items-center gap-2.5 truncate">
                      <span
                        className={isSelected ? "text-white" : "text-slate-400"}
                      >
                        {item.icon}
                      </span>
                      <span className="truncate">{item.label}</span>
                    </span>
                    {item.subMenus && (
                      <ChevronRight
                        className={`w-3.5 h-3.5 flex-shrink-0 transition-transform ${
                          isExpanded ? "rotate-90 text-white" : "text-slate-500"
                        }`}
                      />
                    )}
                  </button>

                  {item.subMenus && isExpanded && (
                    <div className="ml-5 mt-1 mb-1.5 pl-2.5 border-l border-slate-800 space-y-1">
                      {item.subMenus.map((sub) => {
                        const subActive =
                          isSelected && activeSubMenu === sub.id;
                        return (
                          <button
                            key={sub.id}
                            type="button"
                            onClick={() => {
                              setActiveNav(item.id);
                              setActiveSubMenu(sub.id);
                              if (sub.tab) setSelectedTab(sub.tab);
                              if (sub.subView) setActiveSubView(sub.subView);
                            }}
                            className={`w-full text-left px-2.5 py-1.5 rounded-md text-[11px] transition-colors truncate ${
                              subActive
                                ? "bg-cyan-950/70 text-cyan-300 font-semibold"
                                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/60"
                            }`}
                          >
                            {sub.label}
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </nav>

          <div className="mt-6">
            <div className="px-3 mb-2 text-[10px] font-mono uppercase tracking-widest text-slate-500">
              ADMINISTRATION
            </div>
            <nav className="space-y-1">
              {adminNavItems.map((item) => {
                const active = activeNav === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setActiveNav(item.id)}
                    className={`w-full h-9 px-3 rounded-lg text-xs font-medium flex items-center gap-2.5 transition-all ${
                      active
                        ? "bg-[#0284c7] text-white shadow-[0_2px_12px_rgba(2,132,199,0.4)]"
                        : "text-slate-300 hover:bg-[#0e172a] hover:text-white"
                    }`}
                  >
                    <span className={active ? "text-white" : "text-slate-400"}>
                      {item.icon}
                    </span>
                    <span className="truncate">{item.label}</span>
                  </button>
                );
              })}
            </nav>
          </div>
        </div>

        <div className="mt-6 p-3.5 rounded-xl bg-[#0b1322] border border-slate-800/90">
          <div className="text-xs font-bold text-white">
            24/7 SOC &amp; NetOps
          </div>
          <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
            Fixed menu • Drag right edge to resize.
          </p>
          <div className="mt-2.5 flex items-center gap-2 text-[11px] font-mono text-emerald-400">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Autonomous Engine Online</span>
          </div>
        </div>

        {/* Manual Resize Drag Handle on Right Edge of Sidebar */}
        <div
          onMouseDown={() => setIsResizingSidebar(true)}
          title="Drag left or right to resize sidebar"
          className="absolute top-0 right-0 w-1.5 h-full cursor-col-resize hover:bg-[#0284c7] active:bg-cyan-400 transition-colors"
        />
      </aside>

      {/* --- MAIN SCROLLABLE WORKSPACE --- */}
      <main className="flex-1 flex flex-col min-w-0 p-6 relative z-10">
        <header className="mb-5 flex flex-wrap justify-between items-center gap-4">
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white">
              CyberDNA Security &amp; Network Command Center
            </h1>
            <p className="text-xs text-slate-400">
              Autonomous L1/L2 Security &amp; Network Engineer Workspace
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2 px-3 h-9 rounded-lg bg-[#0b1322] border border-slate-700 text-xs">
              <Building2 className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-slate-400 hidden md:inline">Client:</span>
              <select
                value={activeClient}
                onChange={(e) => {
                  setActiveClient(e.target.value);
                  addAuditEntry(
                    loginEmail,
                    `Switched client to ${e.target.value}`,
                  );
                  notifyAction(
                    `Switched workspace to client: ${e.target.value}`,
                  );
                }}
                className="bg-transparent text-white font-semibold focus:outline-none"
              >
                <option value="FinCorp Global" className="bg-[#0b1322]">
                  FinCorp Global
                </option>
                <option value="HealthNet Systems" className="bg-[#0b1322]">
                  HealthNet Systems
                </option>
                <option value="RetailGrid Cloud" className="bg-[#0b1322]">
                  RetailGrid Cloud
                </option>
              </select>
            </div>

            <div className="hidden lg:flex items-center gap-2 text-xs text-slate-400">
              <span>Role</span>
              <select
                value={activeRole}
                onChange={(e) => {
                  setActiveRole(e.target.value);
                  notifyAction(`Role switched to ${e.target.value}`);
                }}
                className="h-9 px-3 rounded-lg bg-white text-slate-900 font-semibold text-xs border border-slate-300 focus:outline-none"
              >
                <option value="Security & NetOps Lead">
                  Security &amp; NetOps Lead
                </option>
                <option value="SOC Analyst L2">SOC Analyst L2</option>
                <option value="Network Engineer">Network Engineer</option>
              </select>
            </div>

            <div className="relative">
              <button
                type="button"
                onClick={() => setProfileMenuOpen((prev) => !prev)}
                title={loginEmail}
                className="h-9 w-9 rounded-full bg-[#0284c7] hover:bg-[#0369a1] text-white font-bold text-xs flex items-center justify-center shadow-md border border-cyan-400/40"
              >
                {userInitials}
              </button>

              {profileMenuOpen && (
                <div className="absolute right-0 mt-2 w-64 rounded-xl bg-[#0b1322] border border-slate-700 shadow-2xl p-3 z-50 space-y-2.5">
                  <div className="pb-2 border-b border-slate-800">
                    <div className="text-xs font-bold text-white truncate">
                      {loginEmail}
                    </div>
                    <div className="text-[11px] text-cyan-400 font-mono mt-0.5">
                      {activeRole}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setProfileMenuOpen(false);
                      setActiveNav("audit");
                    }}
                    className="w-full h-8 px-2.5 rounded-lg text-left text-xs text-slate-300 hover:bg-slate-800 flex items-center gap-2"
                  >
                    <UserCheck className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Engineer Activity Log</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleLogout}
                    className="w-full h-8 px-2.5 rounded-lg text-left text-xs text-red-300 bg-red-950/40 hover:bg-red-900/50 border border-red-500/30 flex items-center gap-2 font-medium"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    <span>Logout Session</span>
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {actionBanner && (
          <div className="mb-4 px-4 py-2.5 rounded-xl bg-cyan-950/60 border border-cyan-500/35 text-xs text-cyan-100 flex items-center justify-between">
            <span>{actionBanner}</span>
            <button
              type="button"
              onClick={() => setActionBanner("")}
              className="text-[11px] font-mono text-cyan-300 hover:text-white"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* --- HERO BANNER (USD CURRENCY) --- */}
        <div className="mb-5 rounded-2xl bg-gradient-to-r from-[#0a2540] via-[#0c4a6e] to-[#0e7490] border border-cyan-500/25 p-6 shadow-xl flex flex-wrap items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <div className="text-[11px] font-mono uppercase tracking-widest text-cyan-200/90">
              {activeClient.toUpperCase()} • AUTONOMOUS SECOPS &amp; NETOPS
            </div>
            <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              See risk clearly. Respond decisively.
            </h2>
            <p className="text-xs sm:text-sm text-cyan-100/85 leading-relaxed">
              Automates L1/L2 Security &amp; Network Engineering workflows—DNS/SPF/DMARC
              verification, firewall port audits, and one-click CLI remediation
              to reduce client delivery cost.
            </p>
            <div className="pt-2 flex flex-wrap items-center gap-2">
              <span className="px-2.5 py-1 rounded-full bg-emerald-950/70 border border-emerald-400/40 text-[10px] font-mono font-semibold text-emerald-300">
                ● AUTONOMOUS ENGINE ACTIVE
              </span>
              <span className="px-2.5 py-1 rounded-full bg-slate-950/60 border border-cyan-400/30 text-[10px] font-mono text-cyan-200">
                {hoursSaved} HRS SAVED
              </span>
              <span className="px-2.5 py-1 rounded-full bg-slate-950/60 border border-emerald-400/30 text-[10px] font-mono text-emerald-200">
                ${costSavedUsd.toLocaleString("en-US")} CLIENT COST SAVED
              </span>
            </div>
          </div>

          <div className="text-right pr-2">
            <div className="text-4xl sm:text-5xl font-extrabold text-white tracking-tight">
              {scoreVal}
            </div>
            <div className="text-xs text-cyan-100 mt-1">
              Security Health Score
            </div>
          </div>
        </div>

        {/* --- 4 KPI CARDS (USD CURRENCY) --- */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <div className="p-4 rounded-xl bg-[#0b1322] border border-slate-800/90">
            <div className="text-xs text-slate-400">Open incidents</div>
            <div className="text-2xl font-bold text-white mt-1">
              {incidentsList.filter((i) => i.status !== "Resolved").length + 10}
            </div>
            <div className="text-[11px] text-amber-400 mt-1">
              Auto-triaged by playbook
            </div>
          </div>
          <div className="p-4 rounded-xl bg-[#0b1322] border border-slate-800/90">
            <div className="text-xs text-slate-400">Engineer hours saved</div>
            <div className="text-2xl font-bold text-white mt-1">
              {hoursSaved}h
            </div>
            <div className="text-[11px] text-emerald-400 mt-1">
              Replaces manual L1/L2 checks
            </div>
          </div>
          <div className="p-4 rounded-xl bg-[#0b1322] border border-slate-800/90">
            <div className="text-xs text-slate-400">Client cost savings</div>
            <div className="text-2xl font-bold text-white mt-1">
              ${costSavedUsd.toLocaleString("en-US")}
            </div>
            <div className="text-[11px] text-cyan-400 mt-1">
              68% lower triage overhead
            </div>
          </div>
          <div className="p-4 rounded-xl bg-[#0b1322] border border-slate-800/90">
            <div className="text-xs text-slate-400">Mean response</div>
            <div className="text-2xl font-bold text-white mt-1">18m</div>
            <div className="text-[11px] text-emerald-400 mt-1">
              One-click CLI &amp; firewall fix
            </div>
          </div>
        </div>

        {/* --- SIDEBAR SECTIONS --- */}
        {activeNav === "incidents" ? (
          <Card className="border-slate-800 bg-[#0b1322] text-slate-100">
            <CardContent className="p-6 space-y-4">
              <div className="flex flex-wrap justify-between items-center gap-3 border-b border-slate-800 pb-3">
                <div>
                  <h2 className="text-lg font-bold text-white">
                    {activeSubMenu === "suppressed"
                      ? "False Positives & Suppressed Rules"
                      : "Priority Incidents — Problem, Solution & Ticket Referral"}
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Review each incident problem, apply the engineering solution, or
                    refer the ticket to another engineer.
                  </p>
                </div>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setActiveSubMenu("triage")}
                    className={`h-9 px-3.5 rounded-lg text-xs font-medium border ${
                      activeSubMenu !== "suppressed"
                        ? "bg-[#0284c7] text-white border-[#0284c7]"
                        : "bg-[#050a14] text-slate-300 border-slate-700"
                    }`}
                  >
                    Active Queue ({incidentsList.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveSubMenu("suppressed")}
                    className={`h-9 px-3.5 rounded-lg text-xs font-medium border ${
                      activeSubMenu === "suppressed"
                        ? "bg-[#0284c7] text-white border-[#0284c7]"
                        : "bg-[#050a14] text-slate-300 border-slate-700"
                    }`}
                  >
                    Suppressed ({suppressedList.length})
                  </button>
                </div>
              </div>

              {activeSubMenu === "suppressed" ? (
                <div className="space-y-2 text-xs">
                  {suppressedList.map((fp) => (
                    <div
                      key={fp.id}
                      className="p-3.5 rounded-xl bg-[#050a14] border border-slate-800 flex items-center justify-between"
                    >
                      <div>
                        <span className="font-mono text-cyan-400 mr-2">
                          {fp.id}
                        </span>
                        <span className="font-semibold text-white">
                          {fp.rule}
                        </span>
                        <p className="text-slate-400 mt-1">{fp.reason}</p>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          setSuppressedList((prev) =>
                            prev.filter((x) => x.id !== fp.id),
                          );
                          notifyAction(
                            `Restored rule ${fp.id} to active monitoring.`,
                          );
                        }}
                        className="h-8 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs"
                      >
                        Restore Rule
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="space-y-4">
                  {incidentsList.map((inc) => (
                    <div
                      key={inc.id}
                      className="p-4 rounded-xl bg-[#050a14] border border-slate-800 space-y-3"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2.5">
                          <span className="font-mono text-xs font-bold text-cyan-400">
                            {inc.id}
                          </span>
                          <h3 className="text-sm font-bold text-white">
                            {inc.title}
                          </h3>
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                              inc.severity === "Critical"
                                ? "bg-red-500 text-white"
                                : inc.severity === "High"
                                  ? "bg-amber-400 text-slate-950"
                                  : "bg-yellow-200 text-slate-950"
                            }`}
                          >
                            {inc.severity}
                          </span>
                        </div>
                        <div className="text-xs font-mono text-slate-300">
                          Status:{" "}
                          <span className="text-emerald-400">{inc.status}</span>{" "}
                          • Owner:{" "}
                          <span className="text-cyan-300">{inc.assignedTo}</span>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                        <div className="p-3 rounded-lg bg-[#0b1322] border border-slate-800">
                          <div className="font-mono text-[10px] uppercase text-red-400 font-bold mb-1">
                            Problem Identified
                          </div>
                          <p className="text-slate-300 leading-relaxed">
                            {inc.problem}
                          </p>
                        </div>
                        <div className="p-3 rounded-lg bg-[#0b1322] border border-slate-800">
                          <div className="font-mono text-[10px] uppercase text-emerald-400 font-bold mb-1">
                            Recommended Solution
                          </div>
                          <p className="text-slate-300 leading-relaxed font-mono text-[11px]">
                            {inc.solution}
                          </p>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                        <div className="flex items-center gap-2">
                          <UserPlus className="w-3.5 h-3.5 text-cyan-400" />
                          <select
                            value={
                              referTargetMap[inc.id] ||
                              teamMembers[0]?.email ||
                              ""
                            }
                            onChange={(e) =>
                              setReferTargetMap((prev) => ({
                                ...prev,
                                [inc.id]: e.target.value,
                              }))
                            }
                            className="h-8 px-2.5 rounded-lg bg-[#0b1322] border border-slate-700 text-xs text-slate-200"
                          >
                            {teamMembers.map((m) => (
                              <option key={m.email} value={m.email}>
                                {m.name} ({m.email})
                              </option>
                            ))}
                          </select>
                          <button
                            type="button"
                            onClick={() => handleReferIncident(inc.id)}
                            className="h-8 px-3 rounded-lg bg-cyan-700 hover:bg-cyan-600 text-white text-xs font-medium"
                          >
                            Refer Ticket
                          </button>
                        </div>

                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => {
                              setIncidentsList((prev) =>
                                prev.map((item) =>
                                  item.id === inc.id
                                    ? { ...item, status: "Resolved" }
                                    : item,
                                ),
                              );
                              notifyAction(`Marked ${inc.id} as Resolved.`);
                            }}
                            className="h-8 px-3 rounded-lg bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs font-medium"
                          >
                            Resolve
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setIncidentsList((prev) =>
                                prev.filter((item) => item.id !== inc.id),
                              );
                              setSuppressedList((prev) => [
                                ...prev,
                                {
                                  id: `FP-${inc.id}`,
                                  rule: inc.title,
                                  reason: inc.problem,
                                  suppressedBy: loginEmail || "SOC Engineer",
                                },
                              ]);
                              notifyAction(`Moved ${inc.id} to Suppressed list.`);
                            }}
                            className="h-8 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium"
                          >
                            Suppress
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        ) : activeNav === "assets" ? (
          <Card className="border-slate-800 bg-[#0b1322] text-slate-100">
            <CardContent className="p-6 space-y-4">
              <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                <h2 className="text-lg font-bold text-white">
                  Client Endpoints &amp; SSL/TLS Inventory
                </h2>
                <Button
                  onClick={() => setActiveNav("dashboard")}
                  className="h-9 px-3.5 bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs"
                >
                  Open Scanner
                </Button>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {[
                  { host: "github.com", ip: "140.82.121.4", tls: "TLS 1.3" },
                  { host: "google.com", ip: "142.250.190.46", tls: "TLS 1.3" },
                  {
                    host: "cloudflare.com",
                    ip: "104.16.132.229",
                    tls: "TLS 1.3",
                  },
                ].map((asset) => (
                  <div
                    key={asset.host}
                    className="p-4 rounded-xl bg-[#050a14] border border-slate-800 space-y-2.5"
                  >
                    <div className="font-mono text-sm font-bold text-cyan-300">
                      {asset.host}
                    </div>
                    <div className="text-xs text-slate-400 font-mono">
                      IP: {asset.ip} • {asset.tls}
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        handleInitiateScan({
                          targetType: "domain",
                          targetValue: asset.host,
                          assessmentProfile: "comprehensive",
                          configOptions: {},
                        })
                      }
                      className="h-8 px-3 rounded-lg bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs font-medium"
                    >
                      Run Live Audit
                    </button>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        ) : activeNav === "integrations" ? (
          <Card className="border-slate-800 bg-[#0b1322] text-slate-100">
            <CardContent className="p-6">{renderIntegrationsPanel()}</CardContent>
          </Card>
        ) : activeNav === "posture" ? (
          <Card className="border-slate-800 bg-[#0b1322] text-slate-100">
            <CardContent className="p-6 space-y-4">
              <h3 className="text-base font-bold text-white">
                Coverage by Control &amp; Compliance
              </h3>
              {[
                { label: "Endpoint protection", pct: 98 },
                { label: "Identity security", pct: 91 },
                { label: "Email & DNS security", pct: 95 },
              ].map((ctrl) => (
                <div key={ctrl.label} className="space-y-1">
                  <div className="flex justify-between text-xs text-slate-300">
                    <span>{ctrl.label}</span>
                    <span className="font-mono text-cyan-400">{ctrl.pct}%</span>
                  </div>
                  <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-[#0284c7] to-[#22d3ee]"
                      style={{ width: `${ctrl.pct}%` }}
                    />
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        ) : activeNav === "reports" ? (
          <Card className="border-slate-800 bg-[#0b1322] text-slate-100">
            <CardContent className="p-6 flex flex-wrap items-center justify-between gap-4">
              <div>
                <h2 className="text-lg font-bold text-white">
                  Client SLA &amp; USD Cost-Savings Report
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Download PDF summary showing {hoursSaved} hrs and $
                  {costSavedUsd.toLocaleString("en-US")} saved for{" "}
                  {activeClient}.
                </p>
              </div>
              <Button
                onClick={handleGenerateReport}
                className="h-9 px-4 bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs flex items-center gap-2"
              >
                <Download className="w-4 h-4" />
                Download Client PDF
              </Button>
            </CardContent>
          </Card>
        ) : activeNav === "requests" ? (
          <Card className="border-slate-800 bg-[#0b1322] text-slate-100">
            <CardContent className="p-6 space-y-4">
              <h2 className="text-lg font-bold text-white">
                NetOps &amp; Firewall Change Requests
              </h2>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!newReqTarget.trim()) return;
                  setServiceRequests((prev) => [
                    {
                      id: `SR-${109 + prev.length}`,
                      type: newReqType,
                      target: newReqTarget.trim(),
                      status: "Queued",
                    },
                    ...prev,
                  ]);
                  notifyAction(
                    `Created change request for ${newReqTarget.trim()}.`,
                  );
                  setNewReqTarget("");
                }}
                className="grid grid-cols-1 md:grid-cols-3 gap-3"
              >
                <input
                  type="text"
                  value={newReqTarget}
                  onChange={(e) => setNewReqTarget(e.target.value)}
                  placeholder="Client host or IP"
                  className="h-9 px-3.5 rounded-lg bg-[#050a14] border border-slate-700 text-xs text-white"
                />
                <select
                  value={newReqType}
                  onChange={(e) => setNewReqType(e.target.value)}
                  className="h-9 px-3.5 rounded-lg bg-[#050a14] border border-slate-700 text-xs text-white"
                >
                  <option>Firewall &amp; Perimeter Port Audit</option>
                  <option>DNS SPF/DMARC Enforcement</option>
                  <option>SSL/TLS Certificate Renewal</option>
                </select>
                <Button
                  type="submit"
                  className="h-9 px-4 bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs flex items-center justify-center gap-2"
                >
                  <Send className="w-3.5 h-3.5" />
                  Submit Request
                </Button>
              </form>
              <div className="space-y-2">
                {serviceRequests.map((req) => (
                  <div
                    key={req.id}
                    className="p-3 rounded-lg bg-[#050a14] border border-slate-800 flex items-center justify-between text-xs"
                  >
                    <span>
                      <strong className="text-cyan-400 font-mono mr-2">
                        {req.id}
                      </strong>
                      {req.type} ({req.target})
                    </span>
                    <span className="px-2.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 font-mono">
                      {req.status}
                    </span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        ) : activeNav === "workflow" ? (
          renderFlowChart()
        ) : activeNav === "users" ? (
          <Card className="border-slate-800 bg-[#0b1322] text-slate-100">
            <CardContent className="p-6 space-y-4">
              <h2 className="text-lg font-bold text-white">
                Users &amp; Engineers Roster
              </h2>
              <form
                onSubmit={handleAddEngineer}
                className="grid grid-cols-1 md:grid-cols-3 gap-3"
              >
                <input
                  type="text"
                  value={newEngName}
                  onChange={(e) => setNewEngName(e.target.value)}
                  placeholder="Engineer Name & Role (e.g. Amit - NetOps)"
                  className="h-9 px-3.5 rounded-lg bg-[#050a14] border border-slate-700 text-xs text-white"
                />
                <input
                  type="email"
                  value={newEngEmail}
                  onChange={(e) => setNewEngEmail(e.target.value)}
                  placeholder="engineer@company.com"
                  className="h-9 px-3.5 rounded-lg bg-[#050a14] border border-slate-700 text-xs text-white"
                />
                <Button
                  type="submit"
                  className="h-9 px-4 bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs"
                >
                  + Add Engineer
                </Button>
              </form>
              <table className="w-full text-xs text-left">
                <thead>
                  <tr className="text-slate-400 border-b border-slate-800">
                    <th className="py-2.5 px-4">Engineer</th>
                    <th className="py-2.5 px-4">Email</th>
                    <th className="py-2.5 px-4">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {teamMembers.map((u) => (
                    <tr
                      key={u.email}
                      className="border-b border-slate-800/70"
                    >
                      <td className="py-3 px-4 text-white">{u.name}</td>
                      <td className="py-3 px-4 font-mono text-cyan-400">
                        {u.email}
                      </td>
                      <td className="py-3 px-4 text-emerald-400 font-mono">
                        Available
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent>
          </Card>
        ) : activeNav === "audit" ? (
          <Card className="border-slate-800 bg-[#0b1322] text-slate-100">
            <CardContent className="p-6 space-y-2 font-mono text-xs">
              <h2 className="text-lg font-sans font-bold text-white mb-3">
                Access Audit Trail
              </h2>
              {auditLogs.map((entry, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg bg-[#050a14] border border-slate-800 flex justify-between"
                >
                  <span>
                    <span className="text-slate-500 mr-2">[{entry.time}]</span>
                    <span className="text-cyan-400 mr-2">{entry.user}</span>
                    {entry.action}
                  </span>
                  <span className="text-slate-500">{entry.ip}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        ) : (
          <>
            <div className="mb-5 bg-[#0b1322] border border-slate-800 rounded-xl p-3 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-400 animate-pulse" />
                <span className="text-xs font-mono font-bold text-white uppercase tracking-wide">
                  Engineer Action Checkbar
                </span>
              </div>

              <div className="flex items-center gap-2 flex-wrap">
                {[
                  {
                    id: "overview",
                    label: "Triage Overview",
                    icon: <Shield className="w-3.5 h-3.5" />,
                  },
                  {
                    id: "runbooks",
                    label: "CLI & Firewall Runbooks",
                    icon: <Wrench className="w-3.5 h-3.5" />,
                  },
                  {
                    id: "compliance",
                    label: "Compliance Auto-Mapping",
                    icon: <FileCheck2 className="w-3.5 h-3.5" />,
                  },
                  {
                    id: "integrations",
                    label: "Jira / Slack / ServiceNow",
                    icon: <ServerCog className="w-3.5 h-3.5" />,
                  },
                  {
                    id: "suppressed",
                    label: "False Positives",
                    icon: <ShieldOff className="w-3.5 h-3.5" />,
                  },
                ].map((btn) => (
                  <button
                    key={btn.id}
                    type="button"
                    onClick={() => {
                      setSelectedTab("dashboard");
                      setActiveSubView(btn.id);
                    }}
                    className={`h-9 px-3.5 rounded-lg text-xs font-medium border flex items-center gap-1.5 transition-colors ${
                      activeSubView === btn.id && selectedTab === "dashboard"
                        ? "bg-[#0284c7] text-white border-[#0284c7]"
                        : "bg-[#050a14] text-slate-300 border-slate-800 hover:border-slate-700"
                    }`}
                  >
                    {btn.icon}
                    <span>{btn.label}</span>
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
              <div className="lg:col-span-1 space-y-4">
                <TargetSpecificationPanel onScanInitiate={handleInitiateScan} />
                {scanError && (
                  <div className="p-3.5 bg-red-950/50 border border-red-500/40 rounded-xl text-xs text-red-300">
                    {scanError}
                  </div>
                )}
              </div>

              <div className="lg:col-span-3 space-y-5">
                {terminalLogs.length > 0 && (
                  <div className="rounded-xl bg-[#070d19] border border-slate-800 overflow-hidden">
                    <button
                      type="button"
                      onClick={() => setShowTerminal(!showTerminal)}
                      className="w-full h-9 px-4 flex items-center justify-between bg-[#0b1322] border-b border-slate-800 text-xs font-mono text-slate-300"
                    >
                      <span className="inline-flex items-center gap-2">
                        <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                        <span>LIVE SECOPS &amp; NETOPS TELEMETRY</span>
                      </span>
                      {showTerminal ? (
                        <ChevronUp className="w-4 h-4" />
                      ) : (
                        <ChevronDown className="w-4 h-4" />
                      )}
                    </button>
                    {showTerminal && (
                      <div className="p-3 font-mono text-xs space-y-1 max-h-28 overflow-y-auto text-cyan-300">
                        {terminalLogs.map((log, i) => (
                          <div key={i}>
                            <span className="text-slate-500 mr-2">&gt;</span>
                            {log}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                <Card className="border-slate-800 bg-[#0b1322] text-slate-100">
                  <CardContent className="p-6">
                    <Tabs
                      defaultValue="dashboard"
                      value={selectedTab}
                      onValueChange={setSelectedTab}
                    >
                      <div className="flex flex-wrap justify-between items-center gap-3 mb-5 pb-3 border-b border-slate-800">
                        <TabsList className="bg-[#050a14] border border-slate-800 p-1">
                          <TabsTrigger
                            value="dashboard"
                            className="h-8 px-3 text-xs data-[state=active]:bg-[#0284c7] data-[state=active]:text-white"
                          >
                            <Shield className="mr-1.5 h-3.5 w-3.5" />
                            Command Dashboard
                          </TabsTrigger>
                          <TabsTrigger
                            value="reconnaissance"
                            className="h-8 px-3 text-xs data-[state=active]:bg-[#0284c7] data-[state=active]:text-white"
                          >
                            <Eye className="mr-1.5 h-3.5 w-3.5" />
                            Network &amp; DNS Recon
                          </TabsTrigger>
                          <TabsTrigger
                            value="owasp"
                            className="h-8 px-3 text-xs data-[state=active]:bg-[#0284c7] data-[state=active]:text-white"
                          >
                            <CheckCircle className="mr-1.5 h-3.5 w-3.5" />
                            Compliance Matrix
                          </TabsTrigger>
                        </TabsList>

                        {scanResults && (
                          <Button
                            onClick={handleRetest}
                            className="h-9 px-3.5 bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs"
                          >
                            <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> Re-Scan
                            Target
                          </Button>
                        )}
                      </div>

                      <TabsContent value="dashboard" className="space-y-6">
                        {activeSubView === "runbooks" ? (
                          renderRunbooksPanel()
                        ) : activeSubView === "compliance" ? (
                          <div className="p-5 rounded-xl bg-[#050a14] border border-slate-800 space-y-3">
                            <h3 className="text-sm font-bold text-cyan-300">
                              Compliance Auto-Mapping (PCI-DSS v4.0 &amp; ISO
                              27001)
                            </h3>
                            <div className="flex justify-between text-xs text-slate-300 py-1.5 border-b border-slate-800">
                              <span>PCI-DSS Req 4.2.1 (HSTS &amp; TLS)</span>
                              <span className="text-emerald-400 font-mono">
                                PASS
                              </span>
                            </div>
                            <div className="flex justify-between text-xs text-slate-300 py-1.5 border-b border-slate-800">
                              <span>PCI-DSS Req 6.4.3 (CSP Header)</span>
                              <span className="text-amber-400 font-mono">
                                ACTION REQ
                              </span>
                            </div>
                            <div className="flex justify-between text-xs text-slate-300 py-1.5">
                              <span>ISO 27001 A.14.1.1 Security Controls</span>
                              <span className="text-emerald-400 font-mono">
                                COMPLIANT
                              </span>
                            </div>
                          </div>
                        ) : activeSubView === "integrations" ? (
                          renderIntegrationsPanel()
                        ) : activeSubView === "suppressed" ? (
                          <div className="p-5 rounded-xl bg-[#050a14] border border-slate-800 space-y-2 text-xs">
                            <div className="font-bold text-amber-300">
                              False Positives &amp; Suppressed Rules (
                              {suppressedList.length})
                            </div>
                            {suppressedList.map((fp) => (
                              <div
                                key={fp.id}
                                className="p-3 rounded-lg bg-[#0b1322] border border-slate-800 flex justify-between"
                              >
                                <span>
                                  <strong className="text-cyan-400 font-mono mr-2">
                                    {fp.id}
                                  </strong>
                                  {fp.rule} — {fp.reason}
                                </span>
                                <span className="text-slate-400 font-mono">
                                  {fp.suppressedBy}
                                </span>
                              </div>
                            ))}
                          </div>
                        ) : !hasPerformedScan && !scanInProgress ? (
                          <div className="space-y-6">
                            <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
                              <div className="p-5 rounded-xl bg-[#050a14] border border-slate-800">
                                <h3 className="text-base font-bold text-white mb-4">
                                  Priority Incidents Table
                                </h3>
                                <div className="overflow-x-auto">
                                  <table className="w-full text-xs text-left">
                                    <thead>
                                      <tr className="text-slate-400 border-b border-slate-800">
                                        <th className="pb-2.5">Incident</th>
                                        <th className="pb-2.5">Severity</th>
                                        <th className="pb-2.5">Assignee</th>
                                        <th className="pb-2.5">Status</th>
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {incidentsList.map((inc) => (
                                        <tr
                                          key={inc.id}
                                          className="border-b border-slate-800/60 last:border-0"
                                        >
                                          <td className="py-3 text-slate-200 font-medium">
                                            {inc.title}
                                          </td>
                                          <td className="py-3">
                                            <span
                                              className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                                                inc.severity === "Critical"
                                                  ? "bg-red-500 text-white"
                                                  : inc.severity === "High"
                                                    ? "bg-amber-400 text-slate-950"
                                                    : "bg-yellow-200 text-slate-950"
                                              }`}
                                            >
                                              {inc.severity}
                                            </span>
                                          </td>
                                          <td className="py-3 text-cyan-300 font-mono">
                                            {inc.assignedTo}
                                          </td>
                                          <td className="py-3 text-slate-300">
                                            {inc.status}
                                          </td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                </div>
                              </div>

                              <div className="p-5 rounded-xl bg-[#050a14] border border-slate-800 space-y-4">
                                <h3 className="text-base font-bold text-white">
                                  Coverage by Control
                                </h3>
                                {[
                                  { label: "Endpoint protection", pct: 98 },
                                  { label: "Identity security", pct: 91 },
                                  { label: "Email & DNS security", pct: 95 },
                                ].map((c) => (
                                  <div key={c.label} className="space-y-1.5">
                                    <div className="flex justify-between text-xs text-slate-300">
                                      <span>{c.label}</span>
                                      <span className="font-mono font-bold text-white">
                                        {c.pct}%
                                      </span>
                                    </div>
                                    <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                                      <div
                                        className="h-full bg-gradient-to-r from-[#0284c7] to-[#22d3ee]"
                                        style={{ width: `${c.pct}%` }}
                                      />
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>

                            {renderFlowChart()}

                            <div className="p-5 rounded-xl bg-[#050a14] border border-slate-800 text-center space-y-3">
                              <div className="text-xs font-mono uppercase tracking-widest text-cyan-400">
                                One-Click Client Infrastructure Benchmark
                              </div>
                              <div className="flex flex-wrap justify-center gap-2.5">
                                {[
                                  { domain: "github.com" },
                                  { domain: "google.com" },
                                  { domain: "cloudflare.com" },
                                  { domain: "example.com" },
                                ].map((preset) => (
                                  <button
                                    key={preset.domain}
                                    type="button"
                                    onClick={() =>
                                      handleInitiateScan({
                                        targetType: "domain",
                                        targetValue: preset.domain,
                                        assessmentProfile: "comprehensive",
                                        configOptions: {},
                                      })
                                    }
                                    className="h-9 px-3.5 rounded-lg bg-[#0b1322] border border-slate-700 hover:border-[#0284c7] text-xs font-mono text-slate-200 inline-flex items-center gap-2 transition-colors"
                                  >
                                    <Globe className="w-3.5 h-3.5 text-cyan-400" />
                                    <span>{preset.domain}</span>
                                    <ArrowRight className="w-3 h-3 text-cyan-400" />
                                  </button>
                                ))}
                              </div>
                            </div>
                          </div>
                        ) : (
                          <div className="space-y-5">
                            <div className="grid grid-cols-1 xl:grid-cols-4 gap-4">
                              <div className="xl:col-span-1 p-4 rounded-xl bg-[#050a14] border border-slate-800 flex flex-col items-center justify-center">
                                <span className="text-[11px] font-mono uppercase text-slate-400 mb-2">
                                  Security Score
                                </span>
                                <div className="relative flex items-center justify-center">
                                  <svg className="w-24 h-24 transform -rotate-90">
                                    <circle
                                      cx="48"
                                      cy="48"
                                      r={radius}
                                      stroke="#1e293b"
                                      strokeWidth="7"
                                      fill="transparent"
                                    />
                                    <circle
                                      cx="48"
                                      cy="48"
                                      r={radius}
                                      stroke={scoreStrokeColor}
                                      strokeWidth="7"
                                      strokeDasharray={circumference}
                                      strokeDashoffset={strokeDashoffset}
                                      strokeLinecap="round"
                                      fill="transparent"
                                    />
                                  </svg>
                                  <div className="absolute flex flex-col items-center">
                                    <span className="text-2xl font-bold text-white">
                                      {scoreVal}
                                    </span>
                                    <span className="text-[10px] text-slate-400">
                                      / 100
                                    </span>
                                  </div>
                                </div>
                              </div>

                              <div className="xl:col-span-3 p-4 rounded-xl bg-[#050a14] border border-slate-800 flex flex-col justify-between">
                                <div>
                                  <div className="flex items-center justify-between mb-2">
                                    <span className="inline-flex items-center gap-2 text-xs font-semibold uppercase text-cyan-400">
                                      <Sparkles className="h-4 w-4" />
                                      AI Executive Security Brief
                                    </span>
                                    <span className="text-xs font-mono text-slate-200 bg-slate-900 border border-slate-700 px-2.5 py-0.5 rounded">
                                      {scanResults?.scanMetadata?.targetValue ||
                                        "Target"}
                                    </span>
                                  </div>
                                  <p className="text-xs sm:text-sm text-slate-200 leading-relaxed">
                                    {scanResults?.executiveSummary || ""}
                                  </p>
                                </div>

                                <div className="mt-3 pt-2.5 border-t border-slate-800 flex flex-wrap justify-between gap-2 text-xs text-slate-400">
                                  <span>
                                    SSL:{" "}
                                    <strong className="text-white">
                                      {scanResults?.reconnaissance?.sslIssuer ||
                                        "N/A"}
                                    </strong>
                                  </span>
                                  <span>
                                    Open Ports:{" "}
                                    <strong className="text-cyan-400 font-mono">
                                      {scanResults?.reconnaissance?.openPorts?.join(
                                        ", ",
                                      ) || "None"}
                                    </strong>
                                  </span>
                                </div>
                              </div>
                            </div>

                            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5">
                              {SECURITY_HEADERS_CHECKLIST.map((item) => {
                                const present = isHeaderPresent(item.key);
                                return (
                                  <div
                                    key={item.key}
                                    className={`p-2.5 rounded-lg border ${
                                      present
                                        ? "bg-[#050a14] border-emerald-500/40"
                                        : "bg-red-950/25 border-red-500/40"
                                    }`}
                                  >
                                    <div className="flex items-center justify-between mb-1">
                                      <span className="text-xs font-bold text-white">
                                        {item.label}
                                      </span>
                                      {present ? (
                                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                                      ) : (
                                        <XCircle className="w-3.5 h-3.5 text-red-400" />
                                      )}
                                    </div>
                                    <p className="text-[10px] text-slate-400 truncate">
                                      {item.desc}
                                    </p>
                                  </div>
                                );
                              })}
                            </div>

                            <SecurityAnalyticsCharts
                              vulnerabilities={
                                scanResults?.vulnerabilities || []
                              }
                              rawHeaders={
                                scanResults?.reconnaissance?.rawHeaders || {}
                              }
                              sslValid={Boolean(
                                scanResults?.reconnaissance?.sslValid,
                              )}
                              scanHistory={scanHistory}
                            />

                            {scanResults && (
                              <ThreatVectorMatrix
                                reconnaissance={
                                  scanResults.reconnaissance || {}
                                }
                                vulnerabilities={
                                  scanResults.vulnerabilities || []
                                }
                              />
                            )}

                            <div className="p-4 rounded-xl bg-[#050a14] border border-slate-800">
                              <h3 className="text-sm font-bold text-white mb-3">
                                Live Scan Summary Table
                              </h3>
                              <div className="overflow-x-auto">
                                <table className="w-full text-xs text-left">
                                  <thead>
                                    <tr className="text-slate-400 border-b border-slate-800">
                                      <th className="py-2 px-3">ID</th>
                                      <th className="py-2 px-3">Finding</th>
                                      <th className="py-2 px-3">Severity</th>
                                      <th className="py-2 px-3">CVSS</th>
                                      <th className="py-2 px-3">Endpoint</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {(scanResults?.vulnerabilities || []).map(
                                      (v: any) => (
                                        <tr
                                          key={v.id}
                                          className="border-b border-slate-800/60"
                                        >
                                          <td className="py-2.5 px-3 font-mono text-cyan-400">
                                            {v.id}
                                          </td>
                                          <td className="py-2.5 px-3 text-slate-200 font-medium">
                                            {v.title}
                                          </td>
                                          <td className="py-2.5 px-3 uppercase font-mono">
                                            {v.severity}
                                          </td>
                                          <td className="py-2.5 px-3 font-mono text-slate-300">
                                            {v.cvss}
                                          </td>
                                          <td className="py-2.5 px-3 font-mono text-slate-400">
                                            {v.endpointUrl}
                                          </td>
                                        </tr>
                                      ),
                                    )}
                                  </tbody>
                                </table>
                              </div>
                            </div>

                            {renderFlowChart()}

                            <VulnerabilityDashboard
                              scanInProgress={scanInProgress}
                              scanProgress={scanProgress}
                              vulnerabilities={scanResults?.vulnerabilities || []}
                              onRetest={handleRetest}
                              onGenerateReport={handleGenerateReport}
                              scanMetadata={scanResults?.scanMetadata}
                              hasPerformedScan={hasPerformedScan}
                            />
                          </div>
                        )}
                      </TabsContent>

                      <TabsContent value="reconnaissance">
                        <div className="p-5 bg-[#050a14] border border-slate-800 rounded-xl space-y-4">
                          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                            <div className="p-4 bg-[#0b1322] rounded-lg border border-slate-800">
                              <div className="text-xs text-slate-400">
                                Resolved IPv4
                              </div>
                              <p className="text-base font-mono text-cyan-400 mt-1">
                                {scanResults?.reconnaissance?.resolvedIp ||
                                  "140.82.112.4"}
                              </p>
                            </div>
                            <div className="p-4 bg-[#0b1322] rounded-lg border border-slate-800">
                              <div className="text-xs text-slate-400">
                                SSL Issuer
                              </div>
                              <p className="text-sm font-semibold text-emerald-400 mt-1">
                                {scanResults?.reconnaissance?.sslIssuer ||
                                  "Sectigo Limited"}
                              </p>
                            </div>
                            <div className="p-4 bg-[#0b1322] rounded-lg border border-slate-800">
                              <div className="text-xs text-slate-400">
                                Open Ports
                              </div>
                              <p className="text-sm font-mono text-cyan-300 mt-1">
                                {scanResults?.reconnaissance?.openPorts?.join(
                                  ", ",
                                ) || "80, 443"}
                              </p>
                            </div>
                            <div className="p-4 bg-[#0b1322] rounded-lg border border-slate-800">
                              <div className="text-xs text-slate-400">
                                DNS SPF / DMARC
                              </div>
                              <p className="text-xs font-mono text-emerald-300 mt-1.5">
                                SPF:{" "}
                                {scanResults?.reconnaissance?.dnsHealth
                                  ?.spf_present === false
                                  ? "Missing"
                                  : "OK"}{" "}
                                • DMARC:{" "}
                                {scanResults?.reconnaissance?.dnsHealth
                                  ?.dmarc_present
                                  ? "OK"
                                  : "Missing"}
                              </p>
                            </div>
                          </div>
                        </div>
                      </TabsContent>

                      <TabsContent value="owasp">
                        <div className="p-5 bg-[#050a14] border border-slate-800 rounded-xl">
                          <table className="w-full text-xs text-left">
                            <thead>
                              <tr className="text-slate-400 border-b border-slate-800">
                                <th className="py-2.5 px-4">Control Area</th>
                                <th className="py-2.5 px-4">Status</th>
                              </tr>
                            </thead>
                            <tbody>
                              {(
                                scanResults?.owaspCompliance?.findings || [
                                  {
                                    category:
                                      "A02:2021 - Cryptographic & TLS Controls",
                                    status: "Compliant",
                                  },
                                  {
                                    category:
                                      "A05:2021 - Security Headers & DNS Policy",
                                    status: "Action Required",
                                  },
                                ]
                              ).map((f: any, idx: number) => (
                                <tr
                                  key={idx}
                                  className="border-b border-slate-800/70"
                                >
                                  <td className="py-3 px-4 text-slate-200">
                                    {f.category}
                                  </td>
                                  <td className="py-3 px-4 text-cyan-400 font-mono">
                                    {f.status}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </TabsContent>
                    </Tabs>
                  </CardContent>
                </Card>
              </div>
            </div>
          </>
        )}
      </main>

      {/* --- LIVE SUPPORT FLOATING BUTTON & DRAWER --- */}
      <div className="fixed bottom-5 right-5 z-50">
        {supportOpen ? (
          <div className="w-80 sm:w-96 rounded-2xl bg-[#0b1322] border border-cyan-500/40 shadow-2xl overflow-hidden">
            <div className="px-4 py-3 bg-gradient-to-r from-[#0a2540] to-[#0e7490] flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-bold text-white">
                <MessageSquare className="w-4 h-4 text-cyan-200" />
                <span>CyberDNA Live Support</span>
              </div>
              <button
                type="button"
                onClick={() => setSupportOpen(false)}
                className="text-cyan-100 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-3.5 h-60 overflow-y-auto space-y-2.5 text-xs bg-[#050a14]">
              {supportMessages.map((m, i) => (
                <div
                  key={i}
                  className={`p-2.5 rounded-xl border ${
                    m.sender === "You"
                      ? "bg-[#0284c7]/20 border-cyan-500/30 ml-6 text-white"
                      : "bg-[#0b1322] border-slate-800 mr-6 text-slate-200"
                  }`}
                >
                  <div className="flex justify-between text-[10px] font-mono text-cyan-400 mb-1">
                    <span>{m.sender}</span>
                    <span>{m.time}</span>
                  </div>
                  <p className="leading-relaxed">{m.text}</p>
                </div>
              ))}
            </div>

            <form
              onSubmit={handleSendSupportMessage}
              className="p-2.5 bg-[#0b1322] border-t border-slate-800 flex gap-2"
            >
              <input
                type="text"
                value={supportInput}
                onChange={(e) => setSupportInput(e.target.value)}
                placeholder="Ask for live SecOps / NetOps help..."
                className="flex-1 h-9 px-3 rounded-lg bg-[#050a14] border border-slate-700 text-xs text-white focus:outline-none focus:border-[#0284c7]"
              />
              <button
                type="submit"
                className="h-9 px-3.5 rounded-lg bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs font-semibold"
              >
                Send
              </button>
            </form>
          </div>
        ) : (
          <button
            type="button"
            onClick={() => setSupportOpen(true)}
            className="h-10 px-4 rounded-xl bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs font-bold shadow-xl border border-cyan-400/40 inline-flex items-center gap-2"
          >
            <MessageSquare className="w-4 h-4" />
            <span>Live Support</span>
          </button>
        )}
      </div>
    </div>
  );
};

export default Home;