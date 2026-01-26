// Core Types for PR Risk Analysis Platform

export type Verdict = "approved" | "blocked" | "manual_review";
export type RiskLevel = "critical" | "high" | "medium" | "low";
export type ScanStatus =
  | "queued"
  | "scanning"
  | "analyzing"
  | "blockchain"
  | "completed"
  | "failed";

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

export interface AIFinding {
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

export interface PRAnalysis {
  id: string;
  prNumber: number;
  title: string;
  description?: string;
  repository: Repository;
  author: Author;
  status: ScanStatus;
  verdict?: Verdict;
  riskScore: number;
  riskLevel: RiskLevel;
  createdAt: string;
  completedAt?: string;
  filesChanged: number;
  additions: number;
  deletions: number;
  snykVulnerabilities: Vulnerability[];
  semgrepFindings: SemgrepFinding[];
  aiFindings: AIFinding[];
  mlRiskFactors: MLRiskFactor[];
  scannerResults: ScannerResult[];
  blockchainVerification?: BlockchainVerification;
  codeDiffs: CodeDiff[];
}

export interface DashboardStats {
  totalPRs: number;
  approved: number;
  blocked: number;
  manualReview: number;
  avgRiskScore: number;
  criticalIssues: number;
  scansTodayAmount: number;
}

export interface AuditLogEntry {
  id: string;
  prId: string;
  prNumber: number;
  repository: Repository;
  verdict: Verdict;
  riskLevel: RiskLevel;
  riskScore: number;
  timestamp: string;
  blockchainStatus: "verified" | "pending" | "failed";
  blockchainHash?: string;
}

export interface FilterOptions {
  verdict?: Verdict | "all";
  riskLevel?: RiskLevel | "all";
  repository?: string | "all";
  dateRange?: {
    start: string;
    end: string;
  };
  search?: string;
}

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

export interface ChartDataPoint {
  date: string;
  value: number;
  label?: string;
}

export interface VerdictDistribution {
  verdict: Verdict;
  count: number;
  percentage: number;
}

export interface SeverityBreakdown {
  severity: RiskLevel;
  count: number;
}
