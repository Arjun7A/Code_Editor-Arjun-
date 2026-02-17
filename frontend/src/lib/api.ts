// API Service Layer - Replace with real API calls
// This simulates API responses for development

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

// Simulated delay for realistic API behavior
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// Generate mock data
function generateMockPRAnalysis(
  id: string,
  prNumber: number
): PRAnalysis {
  const statuses = ["completed"] as const;
  const repos = [
    { name: "api-gateway", owner: "acme-corp" },
    { name: "web-app", owner: "acme-corp" },
    { name: "auth-service", owner: "acme-corp" },
    { name: "payment-service", owner: "acme-corp" },
    { name: "notification-hub", owner: "acme-corp" },
  ];
  const authors = [
    { username: "sarah.chen", reputation: 95 },
    { username: "mike.johnson", reputation: 87 },
    { username: "alex.kumar", reputation: 92 },
    { username: "emma.wilson", reputation: 78 },
    { username: "david.lee", reputation: 89 },
  ];

  const repo = repos[Math.floor(Math.random() * repos.length)];
  const author = authors[Math.floor(Math.random() * authors.length)];
  const riskScore = Math.floor(Math.random() * 100);
  const riskLevel =
    riskScore >= 80
      ? "critical"
      : riskScore >= 60
        ? "high"
        : riskScore >= 40
          ? "medium"
          : "low";
  const verdict =
    riskScore >= 70
      ? "blocked"
      : riskScore >= 50
        ? "manual_review"
        : "approved";

  return {
    id,
    prNumber,
    title: `feat: Update ${repo.name} authentication flow`,
    description: "Implements new OAuth2 flow with PKCE support",
    repository: {
      id: `repo-${id}`,
      name: repo.name,
      owner: repo.owner,
      fullName: `${repo.owner}/${repo.name}`,
      url: `https://github.com/${repo.owner}/${repo.name}`,
    },
    author: {
      id: `author-${id}`,
      username: author.username,
      avatarUrl: `https://api.dicebear.com/7.x/initials/svg?seed=${author.username}`,
      reputation: author.reputation,
    },
    status: statuses[0],
    verdict,
    riskScore,
    riskLevel,
    createdAt: new Date(
      Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000
    ).toISOString(),
    completedAt: new Date().toISOString(),
    filesChanged: Math.floor(Math.random() * 20) + 1,
    additions: Math.floor(Math.random() * 500) + 10,
    deletions: Math.floor(Math.random() * 200) + 5,
    snykVulnerabilities: [
      {
        id: "vuln-1",
        title: "Prototype Pollution in lodash",
        description:
          "Versions of lodash before 4.17.21 are vulnerable to prototype pollution",
        severity: "high",
        cwe: "CWE-1321",
        cvss: 7.4,
        package: "lodash",
        version: "4.17.19",
        fixedVersion: "4.17.21",
      },
      {
        id: "vuln-2",
        title: "Regular Expression Denial of Service",
        description: "The package is vulnerable to ReDoS attacks",
        severity: "medium",
        cwe: "CWE-1333",
        cvss: 5.3,
        package: "validator",
        version: "13.5.0",
        fixedVersion: "13.7.0",
      },
    ],
    semgrepFindings: [
      {
        id: "sem-1",
        ruleId: "javascript.lang.security.audit.sqli",
        message: "Potential SQL injection vulnerability detected",
        severity: "critical",
        path: "src/db/queries.ts",
        startLine: 45,
        endLine: 47,
        snippet: 'const query = `SELECT * FROM users WHERE id = ${userId}`',
      },
      {
        id: "sem-2",
        ruleId: "javascript.express.security.audit.xss",
        message: "Possible XSS vulnerability in response",
        severity: "high",
        path: "src/api/handlers.ts",
        startLine: 112,
        endLine: 114,
      },
    ],
    aiFindings: [
      {
        id: "ai-1",
        type: "security",
        title: "Insecure Token Storage",
        description:
          "Authentication tokens are stored in localStorage which is vulnerable to XSS attacks",
        recommendation:
          "Use httpOnly cookies or secure session storage instead",
        confidence: 0.92,
      },
      {
        id: "ai-2",
        type: "logic",
        title: "Race Condition in State Update",
        description:
          "Multiple concurrent requests may cause inconsistent state updates",
        recommendation:
          "Implement optimistic locking or use atomic operations",
        confidence: 0.85,
      },
    ],
    mlRiskFactors: [
      {
        name: "Files Changed",
        value: 15,
        weight: 0.2,
        contribution: 25,
        description: "Number of files modified in this PR",
      },
      {
        name: "Lines Added",
        value: 450,
        weight: 0.15,
        contribution: 18,
        description: "Total lines of code added",
      },
      {
        name: "Author Reputation",
        value: author.reputation,
        weight: 0.25,
        contribution: -15,
        description: "Historical track record of the author",
      },
      {
        name: "Time Anomaly",
        value: 0.3,
        weight: 0.1,
        contribution: 8,
        description: "Unusual submission time pattern",
      },
      {
        name: "Sensitive Files",
        value: 3,
        weight: 0.3,
        contribution: 35,
        description: "Changes to security-critical files",
      },
    ],
    scannerResults: [
      {
        id: "scan-1",
        name: "Snyk",
        status: "success",
        issuesFound: 2,
        executionTime: 12.4,
        severity: { critical: 0, high: 1, medium: 1, low: 0 },
      },
      {
        id: "scan-2",
        name: "Semgrep",
        status: "success",
        issuesFound: 2,
        executionTime: 8.7,
        severity: { critical: 1, high: 1, medium: 0, low: 0 },
      },
      {
        id: "scan-3",
        name: "LangChain AI",
        status: "success",
        issuesFound: 2,
        executionTime: 23.1,
        severity: { critical: 0, high: 1, medium: 1, low: 0 },
      },
      {
        id: "scan-4",
        name: "ML Risk Engine",
        status: "success",
        issuesFound: 5,
        executionTime: 5.2,
        severity: { critical: 1, high: 2, medium: 1, low: 1 },
      },
    ],
    blockchainVerification: {
      transactionHash:
        "0x7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7890",
      blockNumber: 18234567,
      timestamp: new Date().toISOString(),
      network: "Ethereum Sepolia",
      explorerUrl:
        "https://sepolia.etherscan.io/tx/0x7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7890",
      verified: true,
    },
    codeDiffs: [
      {
        filename: "src/auth/oauth.ts",
        status: "modified",
        additions: 45,
        deletions: 12,
        hunks: [
          {
            oldStart: 10,
            oldLines: 15,
            newStart: 10,
            newLines: 20,
            lines: [
              {
                type: "context",
                content: "import { OAuth2Client } from 'google-auth-library';",
                oldLineNumber: 10,
                newLineNumber: 10,
              },
              {
                type: "deletion",
                content: "const client = new OAuth2Client();",
                oldLineNumber: 11,
              },
              {
                type: "addition",
                content:
                  "const client = new OAuth2Client({ clientId: process.env.CLIENT_ID });",
                newLineNumber: 11,
              },
              {
                type: "addition",
                content: "const pkceVerifier = generatePKCEVerifier();",
                newLineNumber: 12,
              },
              {
                type: "context",
                content: "",
                oldLineNumber: 12,
                newLineNumber: 13,
              },
              {
                type: "context",
                content: "export async function authenticate(code: string) {",
                oldLineNumber: 13,
                newLineNumber: 14,
              },
            ],
          },
        ],
      },
    ],
  };
}

// API Functions
export async function fetchDashboardStats(): Promise<DashboardStats> {
  await delay(800);
  return {
    totalPRs: 1247,
    approved: 892,
    blocked: 156,
    manualReview: 199,
    avgRiskScore: 34.2,
    criticalIssues: 23,
    scansTodayAmount: 47,
  };
}

export async function fetchPRList(
  filters?: FilterOptions
): Promise<PRAnalysis[]> {
  await delay(600);
  const prs: PRAnalysis[] = [];
  for (let i = 1; i <= 12; i++) {
    prs.push(generateMockPRAnalysis(`pr-${i}`, 1000 + i));
  }

  // Apply filters if provided
  let filtered = prs;
  if (filters?.verdict && filters.verdict !== "all") {
    filtered = filtered.filter((pr) => pr.verdict === filters.verdict);
  }
  if (filters?.riskLevel && filters.riskLevel !== "all") {
    filtered = filtered.filter((pr) => pr.riskLevel === filters.riskLevel);
  }
  if (filters?.search) {
    const search = filters.search.toLowerCase();
    filtered = filtered.filter(
      (pr) =>
        pr.title.toLowerCase().includes(search) ||
        pr.repository.name.toLowerCase().includes(search) ||
        pr.author.username.toLowerCase().includes(search)
    );
  }

  return filtered;
}

export async function fetchPRAnalysis(prId: string): Promise<PRAnalysis> {
  await delay(500);
  return generateMockPRAnalysis(prId, parseInt(prId.split("-")[1]) + 1000);
}

export async function fetchAuditLogs(
  filters?: FilterOptions
): Promise<AuditLogEntry[]> {
  await delay(700);
  const logs: AuditLogEntry[] = [];
  for (let i = 1; i <= 50; i++) {
    const pr = generateMockPRAnalysis(`pr-${i}`, 1000 + i);
    logs.push({
      id: `log-${i}`,
      prId: pr.id,
      prNumber: pr.prNumber,
      repository: pr.repository,
      verdict: pr.verdict!,
      riskLevel: pr.riskLevel,
      riskScore: pr.riskScore,
      timestamp: pr.createdAt,
      blockchainStatus: pr.blockchainVerification?.verified
        ? "verified"
        : "pending",
      blockchainHash: pr.blockchainVerification?.transactionHash,
    });
  }

  let filtered = logs;
  if (filters?.verdict && filters.verdict !== "all") {
    filtered = filtered.filter((log) => log.verdict === filters.verdict);
  }
  if (filters?.riskLevel && filters.riskLevel !== "all") {
    filtered = filtered.filter((log) => log.riskLevel === filters.riskLevel);
  }

  return filtered;
}

export async function submitPR(
  _repoUrl: string,
  _prNumber: number
): Promise<{ id: string; status: ScanStatus }> {
  await delay(300);
  return {
    id: `pr-new-${Date.now()}`,
    status: "queued",
  };
}

export async function fetchRiskTrends(): Promise<ChartDataPoint[]> {
  await delay(400);
  const data: ChartDataPoint[] = [];
  for (let i = 29; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    data.push({
      date: date.toISOString().split("T")[0],
      value: Math.floor(Math.random() * 40) + 20,
      label: date.toLocaleDateString("en-US", { month: "short", day: "numeric" }),
    });
  }
  return data;
}

export async function fetchVerdictDistribution(): Promise<VerdictDistribution[]> {
  await delay(350);
  return [
    { verdict: "approved", count: 892, percentage: 71.5 },
    { verdict: "blocked", count: 156, percentage: 12.5 },
    { verdict: "manual_review", count: 199, percentage: 16.0 },
  ];
}

export async function fetchSeverityBreakdown(): Promise<SeverityBreakdown[]> {
  await delay(300);
  return [
    { severity: "critical", count: 23 },
    { severity: "high", count: 67 },
    { severity: "medium", count: 145 },
    { severity: "low", count: 312 },
  ];
}

export async function fetchScannerMetrics(): Promise<
  { name: string; avgTime: number; successRate: number }[]
> {
  await delay(400);
  return [
    { name: "Snyk", avgTime: 12.4, successRate: 99.2 },
    { name: "Semgrep", avgTime: 8.7, successRate: 98.8 },
    { name: "LangChain AI", avgTime: 23.1, successRate: 97.5 },
    { name: "ML Risk Engine", avgTime: 5.2, successRate: 99.9 },
  ];
}

export async function fetchPolicyRules(): Promise<PolicyRule[]> {
  await delay(500);
  return [
    {
      id: "rule-1",
      name: "Block Critical Vulnerabilities",
      description: "Automatically block PRs with critical severity vulnerabilities",
      enabled: true,
      condition: "vulnerability.severity == 'critical'",
      action: "block",
    },
    {
      id: "rule-2",
      name: "Require Review for High Risk",
      description: "Require manual review for PRs with risk score above 70",
      enabled: true,
      condition: "riskScore > 70",
      action: "warn",
    },
    {
      id: "rule-3",
      name: "Allow Trusted Authors",
      description: "Auto-approve PRs from authors with reputation above 90",
      enabled: false,
      condition: "author.reputation > 90",
      action: "allow",
    },
  ];
}

export async function verifyBlockchainRecord(
  _prId: string
): Promise<{ verified: boolean; hash: string; timestamp: string }> {
  await delay(1500);
  return {
    verified: true,
    hash: "0x7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7890",
    timestamp: new Date().toISOString(),
  };
}
