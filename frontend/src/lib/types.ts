export type Severity = "critical" | "high" | "medium" | "low";
export type RiskLevel = Severity;
export type ScanRiskLevel = "low" | "medium" | "high";
export type Verdict = "clean" | "issues_found" | "critical";
export type QuickFilter = "all" | "blocked" | "manual_review";

export interface ScanSummary {
  total_issues: number;
  semgrep: number;
  osv: number;
  ai_agent: number;
  gitleaks: number;
  checkov: number;
  pr_files_scanned: number;
}

export interface IssueFinding {
  tool: string;
  severity: Severity;
  message: string;
  file?: string;
  line?: number;
  rule_id?: string;
  package?: string;
  explanation?: string;
  fix?: string;
}

export interface GitleaksFinding {
  tool: string;
  severity: Severity;
  message: string;
  file?: string;
  line?: number;
  rule_id?: string;
  secret_type?: string;
  redacted?: string;
  explanation?: string;
  fix?: string;
}

export interface CheckovFinding {
  tool: string;
  severity: Severity;
  message: string;
  file?: string;
  line?: number;
  rule_id?: string;
  check_name?: string;
  resource?: string;
  explanation?: string;
  fix?: string;
}

export interface AIFix {
  summary?: string;
  before?: string;
  after?: string;
  steps?: string;
}

export interface AIFinding {
  title: string;
  severity: Severity;
  file?: string;
  category?: string;
  cwe?: string;
  explanation?: string;
  fix?: AIFix | null;
}

export interface AIAudit {
  status: string;
  model?: string | null;
  findings: AIFinding[];
  error?: string | null;
}

export interface ScanRecord {
  repo_url: string;
  pr_url: string;
  scanned_at?: string;
  scan_summary: ScanSummary;
  issues: IssueFinding[];
  ai_audit: AIAudit;
  gitleaks: GitleaksFinding[];
  checkov: CheckovFinding[];
}

export interface DatasetResponse {
  total: number;
  scans: ScanRecord[];
}

export interface RawDashboardStats {
  total_scans: number;
  total_issues: number;
}

export interface DashboardStats {
  totalScans: number;
  totalIssues: number;
}

export interface FilterOptions {
  search?: string;
  repository?: string | "all";
  quickFilter?: QuickFilter;
  riskLevel?: ScanRiskLevel | RiskLevel | "all";
  dateRange?: {
    start: string;
    end: string;
  };
}

export interface ChartDataPoint {
  label: string;
  value: number;
  date?: string;
}

export interface VerdictDistribution {
  label: "LOW" | "MEDIUM" | "HIGH";
  count: number;
  color: string;
}

export interface SeverityBreakdown {
  severity: Severity;
  count: number;
  color: string;
}

export interface ToolMetric {
  name: string;
  count: number;
  color: string;
}

export interface RecentPRRow {
  id: string;
  prId: string;
  prNumber: string;
  repoName: string;
  repoFullName: string;
  repoUrl: string;
  prUrl: string;
  totalIssues: number;
  scanSummary: ScanSummary;
  scannedAt: string;
  riskLevel: ScanRiskLevel;
  verdict: Verdict;
  scan: ScanRecord;
}

export interface AuditLogEntry {
  id: string;
  prId: string;
  prNumber: string;
  repository: string;
  repoUrl: string;
  prUrl: string;
  verdict: Verdict;
  riskLevel: ScanRiskLevel;
  riskScore: number;
  timestamp: string;
  scan: ScanRecord;
}

export type ScanStatus = "queued" | "scanning" | "completed" | "failed";

export interface Author {
  id: string;
  username: string;
  avatarUrl: string;
  reputation: number;
}

export interface Repository {
  id: string;
  name: string;
  owner: string;
  fullName: string;
  url: string;
}

export interface Vulnerability {
  id: string;
  title: string;
  description: string;
  severity: RiskLevel;
  cwe?: string;
  cvss?: number;
  package?: string;
  version?: string;
  fixedVersion?: string;
  path?: string;
  line?: number;
}

export interface SemgrepFinding {
  id: string;
  ruleId: string;
  message: string;
  severity: RiskLevel;
  path: string;
  startLine: number;
  endLine: number;
  snippet?: string;
}

export interface LegacyAIFinding {
  id: string;
  type: "security" | "logic" | "performance" | "best_practice";
  title: string;
  description: string;
  recommendation: string;
  confidence: number;
  affectedCode?: string;
}

export interface MLRiskFactor {
  name: string;
  value: number;
  weight: number;
  contribution: number;
  description: string;
}

export interface ScannerResult {
  id: string;
  name: string;
  status: "success" | "failed" | "skipped";
  issuesFound: number;
  executionTime: number;
  summary?: string;
  severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface BlockchainVerification {
  transactionHash: string;
  blockNumber: number;
  timestamp: string;
  network: string;
  explorerUrl: string;
  verified: boolean;
}

export interface CodeDiff {
  filename: string;
  status: "added" | "modified" | "deleted" | "renamed";
  additions: number;
  deletions: number;
  hunks: DiffHunk[];
}

export interface DiffHunk {
  oldStart: number;
  oldLines: number;
  newStart: number;
  newLines: number;
  lines: DiffLine[];
}

export interface DiffLine {
  type: "context" | "addition" | "deletion";
  content: string;
  oldLineNumber?: number;
  newLineNumber?: number;
}

export type PRAnalysis = ScanRecord;

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  condition: string;
  action: "block" | "warn" | "allow";
}

export interface NotificationPreference {
  id: string;
  type: string;
  enabled: boolean;
  channels: ("email" | "slack" | "webhook")[];
}

export interface APIKey {
  id: string;
  name: string;
  prefix: string;
  createdAt: string;
  lastUsed?: string;
  scopes: string[];
}
