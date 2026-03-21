import { describe, it, expect, beforeEach, vi } from "vitest";

import {
  analyzeGitHubAndMap,
  fetchDashboardStats,
  fetchPRList,
  fetchPolicyRules,
  fetchScannerMetrics,
  fetchVerdictDistribution,
} from "./api";


function mockJsonResponse(payload: unknown) {
  return {
    ok: true,
    status: 200,
    json: async () => payload,
    text: async () => JSON.stringify(payload),
  };
}

function buildBackendPr(overrides: Record<string, unknown> = {}) {
  return {
    id: 1,
    repo_name: "owner/repo",
    pr_number: 10,
    pr_url: "https://github.com/owner/repo/pull/10",
    status: "completed",
    risk_score: 42,
    verdict: "MANUAL_REVIEW",
    author_name: "alice",
    files_changed: 3,
    lines_added: 20,
    lines_deleted: 5,
    feature_importance: {},
    created_at: "2026-02-20T10:00:00Z",
    updated_at: "2026-02-20T10:00:00Z",
    scan_results: [],
    audit_log: null,
    ...overrides,
  };
}


describe("frontend api client", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("throws explicit error when policy endpoint is unavailable", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 503,
      text: async () => "service unavailable",
    });
    vi.stubGlobal("fetch", mockFetch);

    await expect(fetchPolicyRules()).rejects.toThrow(
      "API /policy/rules → 503: service unavailable"
    );
  });

  it("maps dashboard stats without silent fallback defaults", async () => {
    const mockFetch = vi.fn().mockResolvedValue(
      mockJsonResponse({
        total_prs: 10,
        approved: 4,
        blocked: 3,
        manual_review: 3,
        avg_risk_score: 42.5,
        critical_issues: 2,
        scans_today: 1,
        severity_breakdown: {},
        verdict_distribution: [],
        risk_trend: [],
        scanner_stats: {},
      })
    );
    vi.stubGlobal("fetch", mockFetch);

    const stats = await fetchDashboardStats();
    expect(stats.totalPRs).toBe(10);
    expect(stats.avgRiskScore).toBe(42.5);
    expect(stats.criticalIssues).toBe(2);
  });

  it("maps policy actions from backend to frontend values", async () => {
    const mockFetch = vi.fn().mockResolvedValue(
      mockJsonResponse({
        default_action: "MANUAL_REVIEW",
        rules: [
          {
            name: "critical block",
            description: "blocks critical",
            enabled: true,
            priority: 1,
            condition: "critical_count > 0",
            action: "BLOCK",
          },
          {
            name: "safe approve",
            description: "approves low risk",
            enabled: true,
            priority: 2,
            condition: "risk_score < 20",
            action: "AUTO_APPROVE",
          },
        ],
      })
    );
    vi.stubGlobal("fetch", mockFetch);

    const rules = await fetchPolicyRules();
    expect(rules[0].action).toBe("block");
    expect(rules[1].action).toBe("allow");
  });

  it("builds verdict distribution percentages from dashboard payload", async () => {
    const mockFetch = vi.fn().mockResolvedValue(
      mockJsonResponse({
        total_prs: 10,
        approved: 4,
        blocked: 3,
        manual_review: 3,
        avg_risk_score: 40,
        critical_issues: 1,
        scans_today: 2,
        severity_breakdown: {},
        verdict_distribution: [
          { verdict: "AUTO_APPROVE", count: 4 },
          { verdict: "BLOCK", count: 3 },
          { verdict: "MANUAL_REVIEW", count: 3 },
        ],
        risk_trend: [],
        scanner_stats: {},
      })
    );
    vi.stubGlobal("fetch", mockFetch);

    const dist = await fetchVerdictDistribution();
    expect(dist).toEqual([
      { verdict: "approved", count: 4, percentage: 40 },
      { verdict: "blocked", count: 3, percentage: 30 },
      { verdict: "manual_review", count: 3, percentage: 30 },
    ]);
  });

  it("maps scanner metrics with success rate and rounded avg time", async () => {
    const mockFetch = vi.fn().mockResolvedValue(
      mockJsonResponse({
        total_prs: 1,
        approved: 1,
        blocked: 0,
        manual_review: 0,
        avg_risk_score: 10,
        critical_issues: 0,
        scans_today: 1,
        severity_breakdown: {},
        verdict_distribution: [],
        risk_trend: [],
        scanner_stats: {
          snyk: { total: 8, success: 6, avg_time: 1.234 },
          semgrep: { total: 10, success: 10, avg_time: 0.899 },
        },
      })
    );
    vi.stubGlobal("fetch", mockFetch);

    const metrics = await fetchScannerMetrics();
    expect(metrics).toEqual([
      { name: "Snyk", avgTime: 1.2, successRate: 75 },
      { name: "Semgrep", avgTime: 0.9, successRate: 100 },
    ]);
  });

  it("deduplicates PR rows by repo+PR and keeps latest updated record", async () => {
    const mockFetch = vi.fn().mockResolvedValue(
      mockJsonResponse([
        buildBackendPr({
          id: 100,
          risk_score: 20,
          updated_at: "2026-02-20T08:00:00Z",
        }),
        buildBackendPr({
          id: 101,
          risk_score: 70,
          updated_at: "2026-02-20T12:00:00Z",
        }),
      ])
    );
    vi.stubGlobal("fetch", mockFetch);

    const prs = await fetchPRList();
    expect(prs).toHaveLength(1);
    expect(prs[0].riskScore).toBe(70);
  });

  it("sends runtime analysis flags to analyze_github", async () => {
    const mockFetch = vi.fn().mockResolvedValue(
      mockJsonResponse({
        repo: "owner/repo",
        total_prs_analyzed: 0,
        high_risk_count: 0,
        low_risk_count: 0,
        avg_risk_score: 0,
        predictions: [],
      })
    );
    vi.stubGlobal("fetch", mockFetch);

    await analyzeGitHubAndMap("owner/repo", 7, {
      enableAI: false,
      enableML: true,
      enableSecurityScan: false,
    });

    const [_url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(String(init.body));
    expect(body).toMatchObject({
      repo: "owner/repo",
      num_prs: 7,
      enable_ai: false,
      enable_ml: true,
      enable_security_scan: false,
    });
  });

  it("sends target_pr_number when submitting a specific PR", async () => {
    const mockFetch = vi.fn().mockResolvedValue(
      mockJsonResponse({
        repo: "owner/repo",
        total_prs_analyzed: 1,
        high_risk_count: 0,
        low_risk_count: 1,
        avg_risk_score: 0,
        predictions: [],
      })
    );
    vi.stubGlobal("fetch", mockFetch);

    await analyzeGitHubAndMap("owner/repo", 1, {
      targetPrNumber: 321,
      enableAI: true,
      enableML: true,
      enableSecurityScan: true,
    });

    const [_url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(String(init.body));
    expect(body.target_pr_number).toBe(321);
  });
});
