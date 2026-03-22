import type {
  AuditLogEntry,
  ChartDataPoint,
  FilterOptions,
  RecentPRRow,
  ScanRecord,
  ScanRiskLevel,
  ScanSummary,
  Severity,
  SeverityBreakdown,
  ToolMetric,
  Verdict,
  VerdictDistribution,
} from "./types";

export const SEVERITY_META: Record<
  Severity,
  { label: string; color: string }
> = {
  critical: { label: "CRITICAL", color: "#ef4444" },
  high: { label: "HIGH", color: "#f97316" },
  medium: { label: "MEDIUM", color: "#eab308" },
  low: { label: "LOW", color: "#3b82f6" },
};

export const TOOL_META: Record<
  string,
  { label: string; color: string }
> = {
  semgrep: { label: "SEMGREP", color: "#8b5cf6" },
  "osv-scanner": { label: "OSV-SCANNER", color: "#06b6d4" },
  osv: { label: "OSV-SCANNER", color: "#06b6d4" },
  gitleaks: { label: "GITLEAKS", color: "#ef4444" },
  checkov: { label: "CHECKOV", color: "#22c55e" },
  "ai-agent": { label: "AI AGENT", color: "#3b82f6" },
  ai_agent: { label: "AI AGENT", color: "#3b82f6" },
};

const RISK_LEVEL_COLORS: Record<ScanRiskLevel, string> = {
  low: "#3b82f6",
  medium: "#eab308",
  high: "#ef4444",
};

const severityRank: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function safeDate(value?: string): number {
  if (!value) {
    return 0;
  }

  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

export function hexToRgba(hex: string, alpha: number): string {
  const normalized = hex.replace("#", "");
  const safeHex = normalized.length === 3
    ? normalized.split("").map((character) => `${character}${character}`).join("")
    : normalized;

  const red = Number.parseInt(safeHex.slice(0, 2), 16);
  const green = Number.parseInt(safeHex.slice(2, 4), 16);
  const blue = Number.parseInt(safeHex.slice(4, 6), 16);

  return `rgba(${red}, ${green}, ${blue}, ${alpha})`;
}

export function normalizeSeverity(value: string | undefined | null): Severity {
  const normalized = String(value ?? "").toLowerCase();

  if (normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low") {
    return normalized;
  }

  return "low";
}

export function getRepoFullName(repoUrl: string): string {
  try {
    const url = new URL(repoUrl);
    const parts = url.pathname.split("/").filter(Boolean);
    return parts.slice(0, 2).join("/");
  } catch {
    const parts = repoUrl.split("/").filter(Boolean);
    return parts.slice(-2).join("/");
  }
}

export function getRepoName(repoUrl: string): string {
  const fullName = getRepoFullName(repoUrl);
  const parts = fullName.split("/");
  return parts[1] ?? fullName;
}

export function getPrNumber(prUrl: string): string {
  const match = prUrl.match(/\/pull\/(\d+)(?:[/?#]|$)/i);
  return match?.[1] ?? "—";
}

export function formatTimestamp(timestamp?: string): string {
  if (!timestamp) {
    return "Unknown";
  }

  const parsed = Date.parse(timestamp);
  if (!Number.isFinite(parsed)) {
    return timestamp;
  }

  return new Date(parsed).toLocaleString();
}

export function formatFixText(text?: string): string {
  if (!text) {
    return "No remediation guidance was provided.";
  }

  return text
    .replace(/\s*(Step\s+\d+\s+[—-])/g, "\n$1")
    .replace(/\.\s+(Step\s+\d+\s+[—-])/g, ".\n$1")
    .trim();
}

export function getToolSummaryCount(scan: ScanRecord, key: keyof ScanSummary): number {
  const summary = scan.scan_summary ?? ({} as ScanSummary);
  const value = Number(summary[key] ?? 0);
  return Number.isFinite(value) ? value : 0;
}

export function getTotalIssues(scan: ScanRecord): number {
  const summaryValue = Number(scan.scan_summary?.total_issues ?? 0);

  if (Number.isFinite(summaryValue) && summaryValue >= 0) {
    return summaryValue;
  }

  return (
    scan.issues.length +
    scan.gitleaks.length +
    scan.checkov.length +
    (scan.ai_audit?.findings?.length ?? 0)
  );
}

export function getAllSeverities(scan: ScanRecord): Severity[] {
  const issueSeverities = scan.issues.map((issue) => normalizeSeverity(issue.severity));
  const gitleaksSeverities = scan.gitleaks.map((finding) => normalizeSeverity(finding.severity));
  const checkovSeverities = scan.checkov.map((finding) => normalizeSeverity(finding.severity));
  const aiSeverities = (scan.ai_audit?.findings ?? []).map((finding) =>
    normalizeSeverity(finding.severity)
  );

  return [
    ...issueSeverities,
    ...gitleaksSeverities,
    ...checkovSeverities,
    ...aiSeverities,
  ];
}

export function getScanRiskLevel(scan: ScanRecord): ScanRiskLevel {
  const severities = getAllSeverities(scan);

  if (severities.some((severity) => severity === "critical" || severity === "high")) {
    return "high";
  }

  if (severities.some((severity) => severity === "medium")) {
    return "medium";
  }

  return "low";
}

export function getScanVerdict(scan: ScanRecord): Verdict {
  const totalIssues = getTotalIssues(scan);

  if (totalIssues === 0) {
    return "clean";
  }

  return getScanRiskLevel(scan) === "high" ? "critical" : "issues_found";
}

function simpleHash(value: string): string {
  let hash = 0;

  for (let index = 0; index < value.length; index += 1) {
    hash = (hash << 5) - hash + value.charCodeAt(index);
    hash |= 0;
  }

  return Math.abs(hash).toString(36);
}

export function buildScanId(scan: ScanRecord): string {
  const timestampPart = safeDate(scan.scanned_at).toString(36);
  const prPart = getPrNumber(scan.pr_url);
  const hash = simpleHash(`${scan.repo_url}|${scan.pr_url}|${scan.scanned_at ?? ""}`);
  return `scan-${timestampPart}-${prPart}-${hash}`;
}

export function sortScans(scans: ScanRecord[]): ScanRecord[] {
  return [...scans].sort((left, right) => safeDate(right.scanned_at) - safeDate(left.scanned_at));
}

export function filterScans(scans: ScanRecord[], filters: FilterOptions = {}): ScanRecord[] {
  const normalizedSearch = filters.search?.trim().toLowerCase() ?? "";

  return scans.filter((scan) => {
    const repoFullName = getRepoFullName(scan.repo_url).toLowerCase();
    const repoName = getRepoName(scan.repo_url).toLowerCase();
    const prNumber = getPrNumber(scan.pr_url).toLowerCase();
    const scannedAt = scan.scanned_at ?? "";
    const quickFilter = filters.quickFilter ?? "all";
    const riskLevel = getScanRiskLevel(scan);

    if (filters.repository && filters.repository !== "all") {
      const target = filters.repository.toLowerCase();
      if (repoFullName !== target && repoName !== target) {
        return false;
      }
    }

    if (filters.dateRange) {
      const current = safeDate(scannedAt);
      const start = safeDate(filters.dateRange.start);
      const end = safeDate(filters.dateRange.end);

      if (current < start || current > end) {
        return false;
      }
    }

    if (quickFilter === "blocked" && riskLevel !== "high") {
      return false;
    }

    if (quickFilter === "manual_review" && riskLevel !== "medium") {
      return false;
    }

    if (!normalizedSearch) {
      return true;
    }

    return [
      repoFullName,
      repoName,
      scan.pr_url.toLowerCase(),
      prNumber,
      scannedAt.toLowerCase(),
    ].some((value) => value.includes(normalizedSearch));
  });
}

export function toRecentPRRow(scan: ScanRecord): RecentPRRow {
  const repoFullName = getRepoFullName(scan.repo_url);

  return {
    id: buildScanId(scan),
    prId: buildScanId(scan),
    prNumber: getPrNumber(scan.pr_url),
    repoName: getRepoName(scan.repo_url),
    repoFullName,
    repoUrl: scan.repo_url,
    prUrl: scan.pr_url,
    totalIssues: getTotalIssues(scan),
    scanSummary: scan.scan_summary,
    scannedAt: scan.scanned_at ?? "",
    riskLevel: getScanRiskLevel(scan),
    verdict: getScanVerdict(scan),
    scan,
  };
}

export function toAuditLogEntry(scan: ScanRecord): AuditLogEntry {
  return {
    id: buildScanId(scan),
    prId: buildScanId(scan),
    prNumber: getPrNumber(scan.pr_url),
    repository: getRepoName(scan.repo_url),
    repoUrl: scan.repo_url,
    prUrl: scan.pr_url,
    verdict: getScanVerdict(scan),
    riskLevel: getScanRiskLevel(scan),
    riskScore: getTotalIssues(scan),
    timestamp: scan.scanned_at ?? "",
    scan,
  };
}

export function buildRiskTrends(scans: ScanRecord[]): ChartDataPoint[] {
  return sortScans(scans).map((scan) => ({
    label: `#${getPrNumber(scan.pr_url)}`,
    value: getTotalIssues(scan),
    date: scan.scanned_at,
  }));
}

export function buildVerdictDistribution(scans: ScanRecord[]): VerdictDistribution[] {
  const counts: Record<ScanRiskLevel, number> = {
    low: 0,
    medium: 0,
    high: 0,
  };

  scans.forEach((scan) => {
    counts[getScanRiskLevel(scan)] += 1;
  });

  return [
    { label: "LOW", count: counts.low, color: RISK_LEVEL_COLORS.low },
    { label: "MEDIUM", count: counts.medium, color: RISK_LEVEL_COLORS.medium },
    { label: "HIGH", count: counts.high, color: RISK_LEVEL_COLORS.high },
  ];
}

export function buildSeverityBreakdown(scans: ScanRecord[]): SeverityBreakdown[] {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  scans.forEach((scan) => {
    getAllSeverities(scan).forEach((severity) => {
      counts[severity] += 1;
    });
  });

  return (Object.keys(SEVERITY_META) as Severity[]).map((severity) => ({
    severity,
    count: counts[severity],
    color: SEVERITY_META[severity].color,
  }));
}

export function buildToolMetrics(scans: ScanRecord[]): ToolMetric[] {
  const totals = {
    semgrep: 0,
    "osv-scanner": 0,
    gitleaks: 0,
    checkov: 0,
    "ai-agent": 0,
  };

  scans.forEach((scan) => {
    totals.semgrep += getToolSummaryCount(scan, "semgrep");
    totals["osv-scanner"] += getToolSummaryCount(scan, "osv");
    totals.gitleaks += getToolSummaryCount(scan, "gitleaks");
    totals.checkov += getToolSummaryCount(scan, "checkov");
    totals["ai-agent"] += getToolSummaryCount(scan, "ai_agent");
  });

  return Object.entries(totals).map(([tool, count]) => ({
    name: TOOL_META[tool]?.label ?? tool.toUpperCase(),
    count,
    color: TOOL_META[tool]?.color ?? "#94a3b8",
  }));
}

export function getQuickFilterCounts(scans: ScanRecord[]): {
  all: number;
  blocked: number;
  manual_review: number;
} {
  return {
    all: scans.length,
    blocked: scans.filter((scan) => getScanRiskLevel(scan) === "high").length,
    manual_review: scans.filter((scan) => getScanRiskLevel(scan) === "medium").length,
  };
}

export function getSeverityBadgeStyle(severity: Severity): {
  backgroundColor: string;
  color: string;
  borderColor: string;
} {
  const color = SEVERITY_META[severity].color;
  return {
    backgroundColor: hexToRgba(color, 0.16),
    color,
    borderColor: hexToRgba(color, 0.35),
  };
}

export function getToolBadgeStyle(tool: string): {
  backgroundColor: string;
  color: string;
  borderColor: string;
} {
  const meta = TOOL_META[tool] ?? { label: tool.toUpperCase(), color: "#94a3b8" };
  return {
    backgroundColor: hexToRgba(meta.color, 0.16),
    color: meta.color,
    borderColor: hexToRgba(meta.color, 0.35),
  };
}

export function sortIssuesBySeverity<T extends { severity: Severity }>(items: T[]): T[] {
  return [...items].sort((left, right) => severityRank[right.severity] - severityRank[left.severity]);
}
