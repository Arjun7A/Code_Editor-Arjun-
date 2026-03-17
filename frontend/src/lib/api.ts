/**
 * API Service Layer – connects to the real FastAPI backend.
 * Base URL is read from VITE_API_URL (defaults to /api for proxied dev).
 */
import type {
  PRAnalysis,
  DashboardStats,
  AuditLogEntry,
  FilterOptions,
  PolicyRule,
  ChartDataPoint,
  VerdictDistribution,
  SeverityBreakdown,
  ScanStatus,
} from "./types";

const BASE = (import.meta.env.VITE_API_URL ?? "/api").replace(/\/$/, "");

// ─────────────────────────────────────────────────────────────────────────────
//  Shared fetch wrapper
// ─────────────────────────────────────────────────────────────────────────────

type ApiFetchInit = RequestInit & { timeoutMs?: number };

async function apiFetch<T>(path: string, init?: ApiFetchInit): Promise<T> {
  const { timeoutMs = 120000, ...requestInit } = init ?? {};
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...requestInit,
    signal: controller.signal,
  }).catch((err) => {
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new Error(`API ${path} timed out after ${Math.round(timeoutMs / 1000)}s`);
    }
    throw err;
  }).finally(() => {
    clearTimeout(timeout);
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API ${path} → ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Backend response shapes (snake_case from FastAPI)
// ─────────────────────────────────────────────────────────────────────────────

interface BackendStats {
  total_prs: number;
  approved: number;
  blocked: number;
  manual_review: number;
  avg_risk_score: number;
  critical_issues: number;
  scans_today: number;
  severity_breakdown: Record<string, number>;
  verdict_distribution: Array<{ verdict: string; count: number }>;
  risk_trend: Array<{ date: string; value: number; label: string }>;
  scanner_stats: Record<string, { total: number; success?: number; avg_time?: number }>;
}

interface BackendPR {
  id: number;
  repo_name: string;
  pr_number: number;
  pr_url: string;
  status: string;
  risk_score: number | null;
  verdict: string | null;
  author_name: string | null;
  files_changed: number | null;
  lines_added: number | null;
  lines_deleted: number | null;
  feature_importance: Record<string, number> | null;
  created_at: string;
  updated_at: string;
  scan_results: Array<{
    id: number;
    tool: string;
    severity: string | null;
    summary: string | null;
    findings: unknown;
    execution_time: number | null;
    severity_counts: Record<string, number> | null;
    created_at: string;
  }>;
  audit_log?: {
    id: number;
    blockchain_hash: string | null;
    blockchain_tx: string | null;
    decision: string;
    timestamp: string;
    risk_data?: Record<string, unknown> | null;
  } | null;
}

interface BackendScanResponse {
  scan_id: string;
  status: string;
  elapsed_seconds: number;
  snyk_vulnerabilities: unknown[];
  semgrep_findings: unknown[];
  scanner_results: unknown[];
  summary: Record<string, unknown>;
}

interface BackendGitHubResponse {
  repo: string;
  total_prs_analyzed: number;
  high_risk_count: number;
  low_risk_count: number;
  avg_risk_score: number;
  predictions: Array<{
    pr_number: number;
    title: string;
    author: string;
    verdict?: string;
    risk_score: number;
    risk_label: string;
    risk_percentage: number;
    feature_importance: Record<string, number>;
    features: Record<string, unknown>;
    security_findings: string[];
    url: string;
    created_at: string;
    state: string;
    model_version: string;
    using_fallback: boolean;
    snyk_vulnerabilities: Record<string, unknown>[];
    semgrep_findings: Record<string, unknown>[];
    ai_findings: Record<string, unknown>[];
    ai_security_flags?: string[];
    ai_code_smells?: string[];
    ai_provider?: string;
    ai_model?: string | null;
    ai_summary: string;
    ai_status: string;
    scanner_results: Record<string, unknown>[];
  }>;
}

interface AnalyzeGitHubOptions {
  enableAI?: boolean;
  enableML?: boolean;
  enableSecurityScan?: boolean;
  targetPrNumber?: number;
}

interface BackendPolicyRule {
  name: string;
  description: string;
  enabled: boolean;
  priority: number;
  condition: string;
  action: string;
}

interface BackendPolicyResponse {
  default_action: string;
  rules: BackendPolicyRule[];
}

interface BackendVerifyResponse {
  verified: boolean;
  hash: string;
  timestamp: string;
  tx_hash?: string | null;
  block_number?: number | null;
  network?: string;
  explorer_url?: string | null;
  status?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Mappers: backend → frontend types
// ─────────────────────────────────────────────────────────────────────────────

/** Map a backend verdict string to frontend Verdict type */
function mapVerdict(v: string | null | undefined): PRAnalysis["verdict"] {
  if (!v) return undefined;
  const map: Record<string, PRAnalysis["verdict"]> = {
    AUTO_APPROVE: "approved",
    BLOCK: "blocked",
    MANUAL_REVIEW: "manual_review",
    approved: "approved",
    blocked: "blocked",
    manual_review: "manual_review",
  };
  return map[v] ?? "manual_review";
}

function mapRiskLevel(score: number): PRAnalysis["riskLevel"] {
  if (score >= 75) return "critical";
  if (score >= 55) return "high";
  if (score >= 35) return "medium";
  return "low";
}

function mapStatus(s: string): PRAnalysis["status"] {
  const map: Record<string, PRAnalysis["status"]> = {
    pending: "queued",
    scanning: "scanning",
    completed: "completed",
    error: "failed",
    failed: "failed",
  };
  return (map[s] as PRAnalysis["status"]) ?? "queued";
}

function normalizeLayerStatus(value: unknown): PRAnalysis["aiStatus"] | undefined {
  const raw = String(value ?? "").toLowerCase();
  if (raw === "success" || raw === "failed" || raw === "skipped") {
    return raw;
  }
  return undefined;
}

function parseStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => String(item ?? "").trim())
    .filter((item) => item.length > 0);
}

function dedupeStrings(values: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of values) {
    const key = item.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

function isCliUsageText(value: unknown): boolean {
  const text = String(value ?? "").trim().toLowerCase();
  if (!text) return false;
  if (!text.startsWith("usage:")) return false;
  return text.includes("--pr-url") || text.includes("--pr_url") || text.includes("supported git hosting service");
}

function extractRiskData(pr: BackendPR): Record<string, unknown> {
  const audit = pr.audit_log;
  if (!audit?.risk_data || typeof audit.risk_data !== "object") return {};
  return audit.risk_data as Record<string, unknown>;
}

function mapBlockchainVerification(
  pr: BackendPR
): PRAnalysis["blockchainVerification"] | undefined {
  const audit = pr.audit_log;
  if (!audit) return undefined;

  const riskData = extractRiskData(pr);
  const chainMeta =
    riskData["blockchain"] && typeof riskData["blockchain"] === "object"
      ? (riskData["blockchain"] as Record<string, unknown>)
      : {};

  const txHash =
    (typeof audit.blockchain_tx === "string" && audit.blockchain_tx) ||
    (typeof chainMeta["tx_hash"] === "string" ? chainMeta["tx_hash"] : "");
  const recordHash =
    (typeof audit.blockchain_hash === "string" && audit.blockchain_hash) ||
    (typeof chainMeta["record_hash"] === "string" ? chainMeta["record_hash"] : "");
  const rawBlockNumber = chainMeta["block_number"];
  const blockNumber =
    typeof rawBlockNumber === "number"
      ? rawBlockNumber
      : Number(rawBlockNumber ?? 0);
  const network =
    (typeof chainMeta["network"] === "string" && chainMeta["network"]) ||
    "Sepolia";
  const explorerUrl =
    (typeof chainMeta["explorer_url"] === "string" && chainMeta["explorer_url"]) ||
    (txHash ? `https://sepolia.etherscan.io/tx/${txHash}` : "");
  const status =
    (typeof chainMeta["status"] === "string" && chainMeta["status"]) || "";
  const verified = Boolean(txHash) && status !== "failed";

  if (!txHash && !recordHash) return undefined;

  return {
    transactionHash: txHash || recordHash,
    blockNumber: Number.isFinite(blockNumber) ? Math.max(0, blockNumber) : 0,
    timestamp: audit.timestamp,
    network,
    explorerUrl,
    verified,
  };
}

/** Convert a BackendPR into the frontend PRAnalysis shape */
function mapBackendPR(pr: BackendPR): PRAnalysis {
  const riskScore = pr.risk_score ?? 0;
  const repoName = pr.repo_name ?? "unknown/repo";
  const [owner = "unknown", name = "repo"] = repoName.split("/");

  // Build snyk / semgrep / AI findings from stored scan_results
  const snykResult = pr.scan_results?.find((r) => r.tool === "snyk");
  const semgrepResult = pr.scan_results?.find((r) => r.tool === "semgrep");
  const aiAgentResult = pr.scan_results?.find((r) => r.tool === "ai_agent");

  const snykVulnerabilities = Array.isArray(snykResult?.findings)
    ? (snykResult!.findings as PRAnalysis["snykVulnerabilities"])
    : [];

  const semgrepFindings = Array.isArray(semgrepResult?.findings)
    ? (semgrepResult!.findings as PRAnalysis["semgrepFindings"])
    : [];

  // Map AI agent findings to frontend AIFinding shape
  const aiFindings: PRAnalysis["aiFindings"] = Array.isArray(aiAgentResult?.findings)
    ? (aiAgentResult!.findings as Array<Record<string, unknown>>).map((f, i) => ({
        id: (f["id"] as string) ?? `ai-${pr.id}-${i}`,
        type: (["security", "logic", "performance", "best_practice"].includes(f["type"] as string)
          ? f["type"]
          : "security") as PRAnalysis["aiFindings"][number]["type"],
        title: (f["title"] as string) ?? "Finding",
        description: (f["description"] as string) ?? "",
        recommendation: (f["recommendation"] as string) ?? "",
        confidence: typeof f["confidence"] === "number" ? f["confidence"] : 0.5,
        affectedCode: (f["affectedCode"] as string | undefined) ?? undefined,
      }))
    : [];

  const riskData = extractRiskData(pr);
  const aiStatusFromAudit = normalizeLayerStatus(riskData["ai_status"]);
  const aiSummaryFromAudit =
    typeof riskData["ai_summary"] === "string" ? String(riskData["ai_summary"]) : "";
  const aiProviderFromAudit =
    typeof riskData["ai_provider"] === "string" ? String(riskData["ai_provider"]) : "";
  const aiModelFromAudit =
    typeof riskData["ai_model"] === "string" ? String(riskData["ai_model"]) : null;

  const aiSummaryFromScanResult =
    typeof aiAgentResult?.summary === "string" ? aiAgentResult.summary : "";

  const aiSummaryRaw = (aiSummaryFromAudit || aiSummaryFromScanResult).trim();
  const aiSummary = isCliUsageText(aiSummaryRaw) ? "" : aiSummaryRaw;
  const inferredAiStatus: PRAnalysis["aiStatus"] =
    ((isCliUsageText(aiSummaryRaw)
      || aiSummaryFromScanResult.toLowerCase().includes("failed")
      || aiSummaryFromScanResult.toLowerCase().includes("error"))
      ? "failed"
      : (aiFindings.length > 0 || aiSummary ? "success" : "skipped"));
  const aiStatus = isCliUsageText(aiSummaryRaw) ? "failed" : (aiStatusFromAudit ?? inferredAiStatus);

  const aiSecurityFlagsFromAudit = parseStringArray(riskData["ai_security_flags"]);
  const aiCodeSmellsFromAudit = parseStringArray(riskData["ai_code_smells"]);
  const aiSecurityFlagsFromFindings = aiFindings
    .filter((finding) => finding.type === "security")
    .map((finding) => (finding.title || finding.description || "").trim())
    .filter((text) => text.length > 0);
  const aiCodeSmellsFromFindings = aiFindings
    .filter((finding) => finding.type === "best_practice")
    .map((finding) => (finding.title || finding.description || "").trim())
    .filter((text) => text.length > 0);
  const aiSecurityFlags = dedupeStrings(
    aiSecurityFlagsFromAudit.length > 0 ? aiSecurityFlagsFromAudit : aiSecurityFlagsFromFindings
  );
  const aiCodeSmells = dedupeStrings(
    aiCodeSmellsFromAudit.length > 0 ? aiCodeSmellsFromAudit : aiCodeSmellsFromFindings
  );
  const aiProvider = (aiProviderFromAudit || (aiAgentResult ? "pr-agent" : "")).trim();
  const aiModel = aiModelFromAudit;

  // Build ScannerResult[] from stored scan results — use real severity_counts and execution_time
  const scannerResults: PRAnalysis["scannerResults"] = pr.scan_results
    ?.filter((r) => r.tool !== "summary")
    .map((r, i) => {
      const findings = Array.isArray(r.findings) ? r.findings : [];
      const sc = r.severity_counts ?? {};
      const summaryText = (r.summary ?? "").toLowerCase();
      let status: "success" | "failed" | "skipped" =
        summaryText.includes("failed") || summaryText.includes("error")
          ? "failed"
          : r.severity_counts !== null
            ? "success"
            : "skipped";
      if (r.tool === "ai_agent") {
        status = aiStatus ?? status;
      }
      const toolName =
        r.tool === "snyk" ? "Snyk"
        : r.tool === "semgrep" ? "Semgrep"
        : r.tool === "ai_agent" ? "PR-Agent"
        : r.tool;
      const summary =
        r.tool === "ai_agent" && aiSummary
          ? aiSummary
          : r.summary ?? undefined;
      return {
        id: `sr-${pr.id}-${i}`,
        name: toolName,
        status,
        issuesFound: findings.length,
        executionTime: r.execution_time ?? 0,
        summary,
        severity: {
          critical: sc["critical"] ?? 0,
          high: sc["high"] ?? 0,
          medium: sc["medium"] ?? 0,
          low: sc["low"] ?? 0,
        },
      };
    }) ?? [];

  const authorName = pr.author_name ?? "unknown";

  return {
    id: String(pr.id),
    prNumber: pr.pr_number,
    title: `PR #${pr.pr_number} – ${repoName}`,
    repository: {
      id: `repo-${pr.id}`,
      name,
      owner,
      fullName: repoName,
      url: `https://github.com/${repoName}`,
    },
    author: {
      id: `author-${pr.id}`,
      username: authorName,
      avatarUrl: `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(authorName)}`,
      reputation: Math.max(0, Math.round(100 - riskScore)),
    },
    status: mapStatus(pr.status),
    verdict: mapVerdict(pr.verdict),
    riskScore,
    riskLevel: mapRiskLevel(riskScore),
    createdAt: pr.created_at,
    completedAt: pr.updated_at,
    filesChanged: pr.files_changed ?? 0,
    additions: pr.lines_added ?? 0,
    deletions: pr.lines_deleted ?? 0,
    snykVulnerabilities,
    semgrepFindings,
    aiFindings,
    aiSecurityFlags,
    aiCodeSmells,
    aiSummary,
    aiStatus,
    aiProvider: aiProvider || undefined,
    aiModel,
    mlRiskFactors: Object.entries(pr.feature_importance ?? {}).map(([fname, fval]) => ({
      name: fname.replace(/_/g, " "),
      value: typeof fval === "number" ? fval : 0,
      weight: 0.1,
      contribution: Math.round((typeof fval === "number" ? fval : 0) * 1000) / 10,
      description: fname.replace(/_/g, " "),
    })),
    scannerResults,
    blockchainVerification: mapBlockchainVerification(pr),
    codeDiffs: [],
  };
}

/** Map a GitHub analyze prediction to PRAnalysis */
function mapGitHubPrediction(
  pred: BackendGitHubResponse["predictions"][number],
  repo: string
): PRAnalysis {
  const riskScore = Math.round(pred.risk_percentage ?? pred.risk_score * 100);
  const mappedVerdict = mapVerdict(pred.verdict ?? null);
  const [owner = "unknown", name = repo] = repo.split("/");

  // Use real scanner findings from backend; only fall back to heuristic text if none returned
  const snykVulnerabilities = (pred.snyk_vulnerabilities ?? []) as PRAnalysis["snykVulnerabilities"];

  const semgrepFindings =
    (pred.semgrep_findings ?? []) as PRAnalysis["semgrepFindings"];

  const aiFindings: PRAnalysis["aiFindings"] = Array.isArray(pred.ai_findings)
    ? pred.ai_findings.map((f, i) => ({
        id: (f["id"] as string) ?? `ai-gh-${pred.pr_number}-${i}`,
        type: (["security", "logic", "performance", "best_practice"].includes(f["type"] as string)
          ? f["type"]
          : "security") as PRAnalysis["aiFindings"][number]["type"],
        title: (f["title"] as string) ?? "Finding",
        description: (f["description"] as string) ?? "",
        recommendation: (f["recommendation"] as string) ?? "",
        confidence: typeof f["confidence"] === "number" ? f["confidence"] : 0.5,
        affectedCode: (f["affectedCode"] as string | undefined) ?? undefined,
      }))
    : [];

  const aiStatus = normalizeLayerStatus(pred.ai_status) ?? "skipped";
  const aiProvider = (pred.ai_provider ?? "pr-agent").trim();
  const aiModel = pred.ai_model ?? null;
  const aiSummaryRaw = (pred.ai_summary ?? "").trim();
  const aiSummary = isCliUsageText(aiSummaryRaw) ? "" : aiSummaryRaw;
  const aiSecurityFlags = dedupeStrings(
    (parseStringArray(pred.ai_security_flags).length > 0
      ? parseStringArray(pred.ai_security_flags)
      : aiFindings
          .filter((finding) => finding.type === "security")
          .map((finding) => (finding.title || finding.description || "").trim())
          .filter((text) => text.length > 0))
  );
  const aiCodeSmells = dedupeStrings(
    (parseStringArray(pred.ai_code_smells).length > 0
      ? parseStringArray(pred.ai_code_smells)
      : aiFindings
          .filter((finding) => finding.type === "best_practice")
          .map((finding) => (finding.title || finding.description || "").trim())
          .filter((text) => text.length > 0))
  );

  // Use real scanner results from the backend if present.
  const scannerResults: PRAnalysis["scannerResults"] = (pred.scanner_results ?? []).map((r, i) => {
    const rawName = String(r["name"] ?? "").trim();
    const rawTool = String(r["tool"] ?? "").trim().toLowerCase();
    const isAiRow = rawTool === "ai_agent" || rawName.toLowerCase() === "ai agent" || rawName.toLowerCase() === "pr-agent";
    const rawStatus = String(r["status"] ?? "").toLowerCase();
    const status: "success" | "failed" | "skipped" =
      isAiRow
        ? aiStatus
        : (rawStatus === "success" || rawStatus === "failed" || rawStatus === "skipped")
          ? rawStatus
          : "success";
    const severityValue = r["severity"];
    const severityMap =
      severityValue && typeof severityValue === "object"
        ? (severityValue as Record<string, unknown>)
        : {};

    return {
      id: String(r["id"] ?? `sr-gh-${pred.pr_number}-${i}`),
      name: isAiRow
        ? "PR-Agent"
        : (rawName || (rawTool === "snyk" ? "Snyk" : rawTool === "semgrep" ? "Semgrep" : "Scanner")),
      status,
      issuesFound: Number(r["issuesFound"] ?? 0) || 0,
      executionTime: Number(r["executionTime"] ?? 0) || 0,
      summary: isAiRow ? aiSummary : (typeof r["summary"] === "string" ? r["summary"] : undefined),
      severity: {
        critical: Number(severityMap["critical"] ?? 0) || 0,
        high: Number(severityMap["high"] ?? 0) || 0,
        medium: Number(severityMap["medium"] ?? 0) || 0,
        low: Number(severityMap["low"] ?? 0) || 0,
      },
    };
  });

  return {
    id: `gh-${repo}-${pred.pr_number}`,
    prNumber: pred.pr_number,
    title: pred.title || `PR #${pred.pr_number}`,
    repository: {
      id: `repo-${repo}`,
      name,
      owner,
      fullName: repo,
      url: `https://github.com/${repo}`,
    },
    author: {
      id: `author-${pred.author}`,
      username: pred.author,
      avatarUrl: `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(pred.author)}`,
      reputation: Math.round((pred.features?.author_reputation as number ?? 0.5) * 100),
    },
    status: "completed",
    verdict: mappedVerdict ?? "manual_review",
    riskScore,
    riskLevel: mapRiskLevel(riskScore),
    createdAt: pred.created_at,
    completedAt: pred.created_at,
    filesChanged: (pred.features?.files_changed as number) ?? 0,
    additions: (pred.features?.lines_added as number) ?? 0,
    deletions: (pred.features?.lines_deleted as number) ?? 0,
    snykVulnerabilities,
    semgrepFindings,
    aiFindings,
    aiSecurityFlags,
    aiCodeSmells,
    aiSummary,
    aiStatus,
    aiProvider,
    aiModel,
    mlRiskFactors: Object.entries(pred.feature_importance ?? {}).map(([fname, fval]) => ({
      name: fname.replace(/_/g, " "),
      value: typeof fval === "number" ? fval : 0,
      weight: typeof fval === "number" ? Math.min(1, Math.abs(fval)) : 0,
      contribution: Math.round((typeof fval === "number" ? fval : 0) * 1000) / 10,
      description: fname.replace(/_/g, " "),
    })),
    scannerResults,
    codeDiffs: [],
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Public API functions
// ─────────────────────────────────────────────────────────────────────────────

export async function fetchDashboardStats(): Promise<DashboardStats> {
  const data = await apiFetch<BackendStats>("/dashboard-stats", { timeoutMs: 30000 });
  return {
    totalPRs: data.total_prs,
    approved: data.approved,
    blocked: data.blocked,
    manualReview: data.manual_review,
    avgRiskScore: data.avg_risk_score,
    criticalIssues: data.critical_issues,
    scansTodayAmount: data.scans_today,
  };
}

export async function fetchPRList(filters?: FilterOptions): Promise<PRAnalysis[]> {
  const params = new URLSearchParams({ skip: "0", limit: "200" });
  // Extended timeout for fetching 200 PRs with all their relationships
  const raw = await apiFetch<BackendPR[]>(`/results?${params}`, { timeoutMs: 60000 });
  const mapped = raw.map(mapBackendPR);

  // Guard against legacy duplicate DB rows for the same repo+PR.
  // Keep the most recently completed/updated one.
  const byPrKey = new Map<string, PRAnalysis>();
  for (const pr of mapped) {
    const key = `${pr.repository.fullName}#${pr.prNumber}`;
    const current = byPrKey.get(key);
    if (!current) {
      byPrKey.set(key, pr);
      continue;
    }
    const currentTs = Date.parse(current.completedAt ?? current.createdAt);
    const candidateTs = Date.parse(pr.completedAt ?? pr.createdAt);
    if ((Number.isFinite(candidateTs) ? candidateTs : 0) >= (Number.isFinite(currentTs) ? currentTs : 0)) {
      byPrKey.set(key, pr);
    }
  }
  let prs = Array.from(byPrKey.values());

  if (filters?.verdict && filters.verdict !== "all") {
    prs = prs.filter((pr) => pr.verdict === filters.verdict);
  }
  if (filters?.riskLevel && filters.riskLevel !== "all") {
    prs = prs.filter((pr) => pr.riskLevel === filters.riskLevel);
  }
  if (filters?.repository && filters.repository !== "all") {
    const repoFilter = filters.repository.toLowerCase();
    prs = prs.filter((pr) => {
      const fullName = pr.repository.fullName.toLowerCase();
      const name = pr.repository.name.toLowerCase();
      return fullName === repoFilter || name === repoFilter;
    });
  }
  if (filters?.search) {
    const search = filters.search.toLowerCase();
    prs = prs.filter(
      (pr) =>
        pr.title.toLowerCase().includes(search) ||
        pr.repository.name.toLowerCase().includes(search) ||
        pr.author.username.toLowerCase().includes(search)
    );
  }

  return prs;
}

export async function fetchPRAnalysis(prId: string): Promise<PRAnalysis> {
  // prId may be a plain DB id (e.g. "3") or a GitHub-analyzer composite id
  if (prId.startsWith("gh-")) {
    throw new Error("GitHub-sourced PRs are not stored in DB");
  }
  const raw = await apiFetch<BackendPR>(`/results/${prId}`, { timeoutMs: 30000 });
  const requested = Number(prId);
  if (Number.isInteger(requested) && requested > 0 && raw.pr_number !== requested) {
    try {
      const list = await apiFetch<BackendPR[]>("/results?skip=0&limit=200", { timeoutMs: 60000 });
      const sameRepo = list.filter(
        (pr) => pr.repo_name === raw.repo_name && pr.pr_number === requested
      );
      const fallbackPool = sameRepo.length > 0
        ? sameRepo
        : list.filter((pr) => pr.pr_number === requested);
      if (fallbackPool.length > 0) {
        const latest = fallbackPool.sort(
          (a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at)
        )[0];
        return mapBackendPR(latest);
      }
    } catch {
      // keep default behavior if fallback lookup fails
    }
  }
  return mapBackendPR(raw);
}

export async function fetchAuditLogs(
  filters?: FilterOptions
): Promise<AuditLogEntry[]> {
  const raw = await apiFetch<BackendPR[]>("/results?skip=0&limit=200", { timeoutMs: 60000 });
  let logs: AuditLogEntry[] = raw.map((pr) => {
    const audit = pr.audit_log;
    const riskData =
      audit?.risk_data && typeof audit.risk_data === "object"
        ? (audit.risk_data as Record<string, unknown>)
        : {};
    const chainMeta =
      riskData["blockchain"] && typeof riskData["blockchain"] === "object"
        ? (riskData["blockchain"] as Record<string, unknown>)
        : {};
    const txHash =
      (typeof audit?.blockchain_tx === "string" && audit.blockchain_tx) ||
      (typeof chainMeta["tx_hash"] === "string" ? chainMeta["tx_hash"] : undefined);
    const recordHash =
      (typeof audit?.blockchain_hash === "string" && audit.blockchain_hash) ||
      (typeof chainMeta["record_hash"] === "string" ? chainMeta["record_hash"] : undefined);
    const chainStatus =
      (typeof chainMeta["status"] === "string" && chainMeta["status"]) || "";

    const blockchainStatus: AuditLogEntry["blockchainStatus"] = txHash
      ? "verified"
      : chainStatus === "failed"
        ? "failed"
        : "pending";

    return {
      id: String(pr.id),
      prId: String(pr.id),
      prNumber: pr.pr_number,
      repository: {
        id: `repo-${pr.id}`,
        name: (pr.repo_name ?? "repo").split("/")[1] ?? "repo",
        owner: (pr.repo_name ?? "unknown/repo").split("/")[0],
        fullName: pr.repo_name ?? "unknown/repo",
        url: `https://github.com/${pr.repo_name}`,
      },
      verdict: mapVerdict(pr.verdict) ?? "manual_review",
      riskLevel: mapRiskLevel(pr.risk_score ?? 0),
      riskScore: pr.risk_score ?? 0,
      timestamp: audit?.timestamp ?? pr.created_at,
      blockchainStatus,
      blockchainHash: txHash ?? recordHash,
    };
  });

  if (filters?.verdict && filters.verdict !== "all") {
    logs = logs.filter((l) => l.verdict === filters.verdict);
  }
  if (filters?.riskLevel && filters.riskLevel !== "all") {
    logs = logs.filter((l) => l.riskLevel === filters.riskLevel);
  }

  return logs;
}

export async function submitPR(
  repoUrl: string,
  prNumber: number
): Promise<{ id: string; status: ScanStatus }> {
  // Parse owner/repo from URL
  const match = repoUrl.match(/github\.com\/([^/]+\/[^/]+)/);
  const repoName = match ? match[1].replace(/\.git$/, "") : repoUrl;

  const res = await apiFetch<{ id: number; status: string }>("/analyze", {
    method: "POST",
    body: JSON.stringify({
      repo_name: repoName,
      pr_number: prNumber,
      pr_url: repoUrl,
    }),
    timeoutMs: 30000,
  });

  return { id: String(res.id), status: mapStatus(res.status) };
}

export async function submitPRForAIOnly(
  repoUrl: string,
  prNumber: number
): Promise<{ id: string; status: ScanStatus }> {
  // Parse owner/repo from URL
  const match = repoUrl.match(/github\.com\/([^/]+\/[^/]+)/);
  const repoName = match ? match[1].replace(/\.git$/, "") : repoUrl;

  const res = await apiFetch<{ id: number; status: string }>("/analyze_ai_only", {
    method: "POST",
    body: JSON.stringify({
      repo_name: repoName,
      pr_number: prNumber,
      pr_url: repoUrl,
    }),
    timeoutMs: 30000,
  });

  return { id: String(res.id), status: mapStatus(res.status) };
}

export async function fetchRiskTrends(): Promise<ChartDataPoint[]> {
  const data = await apiFetch<BackendStats>("/dashboard-stats");
  return (data.risk_trend ?? []).map((r) => ({
    date: r.date,
    value: r.value,
    label: r.label,
  }));
}

export async function fetchVerdictDistribution(): Promise<VerdictDistribution[]> {
  const data = await apiFetch<BackendStats>("/dashboard-stats");
  const dist = data.verdict_distribution ?? [];
  const total = dist.reduce((s, d) => s + d.count, 0) || 1;
  const verdictMap: Record<string, VerdictDistribution["verdict"]> = {
    AUTO_APPROVE: "approved",
    BLOCK: "blocked",
    MANUAL_REVIEW: "manual_review",
  };
  return dist.map((d) => ({
    verdict: (verdictMap[d.verdict] ?? d.verdict) as VerdictDistribution["verdict"],
    count: d.count,
    percentage: Math.round((d.count / total) * 1000) / 10,
  }));
}

export async function fetchSeverityBreakdown(): Promise<SeverityBreakdown[]> {
  const data = await apiFetch<BackendStats>("/dashboard-stats");
  const breakdown = data.severity_breakdown ?? {};
  return (["critical", "high", "medium", "low"] as const).map((sev) => ({
    severity: sev,
    count: breakdown[sev] ?? 0,
  }));
}

export async function fetchScannerMetrics(): Promise<
  { name: string; avgTime: number; successRate: number }[]
> {
  const data = await apiFetch<BackendStats>("/dashboard-stats");
  const stats = data.scanner_stats ?? {};
  return (["snyk", "semgrep"] as const).map((tool) => {
    const s = stats[tool];
    const total = s?.total ?? 0;
    const success = s?.success ?? total;
    const avgTime = s?.avg_time ?? 0;
    return {
      name: tool === "snyk" ? "Snyk" : "Semgrep",
      avgTime: Math.round(avgTime * 10) / 10,
      successRate: total > 0 ? Math.round((success / total) * 100) : 0,
    };
  });
}

export async function fetchPolicyRules(): Promise<PolicyRule[]> {
  const data = await apiFetch<BackendPolicyResponse>("/policy/rules", { timeoutMs: 30000 });
  const actionMap: Record<string, PolicyRule["action"]> = {
    BLOCK: "block",
    MANUAL_REVIEW: "warn",
    AUTO_APPROVE: "allow",
  };

  return (data.rules ?? []).map((rule, idx) => ({
    id: `rule-${idx + 1}`,
    name: rule.name,
    description: rule.description,
    enabled: Boolean(rule.enabled),
    condition: rule.condition,
    action: actionMap[rule.action] ?? "warn",
  }));
}

export async function verifyBlockchainRecord(
  prId: string
): Promise<{ verified: boolean; hash: string; timestamp: string }> {
  const idMatch = prId.match(/\d+/);
  if (!idMatch) {
    return {
      verified: false,
      hash: "",
      timestamp: new Date().toISOString(),
    };
  }

  const result = await apiFetch<BackendVerifyResponse>(
    `/blockchain/verify/${idMatch[0]}`,
    { timeoutMs: 30000 }
  );

  return {
    verified: Boolean(result.verified),
    hash: result.hash ?? result.tx_hash ?? "",
    timestamp: result.timestamp ?? new Date().toISOString(),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Direct scan (used from Submit page after GitHub analysis)
// ─────────────────────────────────────────────────────────────────────────────

export async function scanCode(
  options: { code?: string; repoUrl?: string; filename?: string }
): Promise<BackendScanResponse> {
  // Ensure repo_url is always a full clonable URL
  let repoUrl = options.repoUrl;
  if (repoUrl && !repoUrl.startsWith("http")) {
    repoUrl = `https://github.com/${repoUrl}`;
  }

  // Use extended timeout for scan (120s clone + 120s scanning + buffer = 300s)
  return apiFetch<BackendScanResponse>("/scan", {
    method: "POST",
    body: JSON.stringify({
      code: options.code,
      repo_url: repoUrl,
      filename: options.filename ?? "code.py",
    }),
    timeoutMs: 300000, // 5 minutes for clone + scanners
  });
}

// ─────────────────────────────────────────────────────────────────────────────
//  GitHub Analyzer  (existing endpoint – re-exported for convenience)
// ─────────────────────────────────────────────────────────────────────────────

export async function analyzeGitHubAndMap(
  repo: string,
  numPrs = 10,
  options: AnalyzeGitHubOptions = {}
): Promise<{ raw: BackendGitHubResponse; prs: PRAnalysis[] }> {
  const raw = await apiFetch<BackendGitHubResponse>("/analyze_github", {
    method: "POST",
    timeoutMs: 240000,
    body: JSON.stringify({
      repo,
      num_prs: numPrs,
      target_pr_number: options.targetPrNumber,
      enable_ai: options.enableAI ?? true,
      enable_ml: options.enableML ?? true,
      enable_security_scan: options.enableSecurityScan ?? true,
    }),
  });

  const prs = raw.predictions.map((p) => mapGitHubPrediction(p, repo));
  return { raw, prs };
}
