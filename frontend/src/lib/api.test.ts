import { beforeEach, describe, expect, it, vi } from "vitest";
import { analyzePR, fetchPRAnalysis, getDashboardStats, getDataset } from "./api";
import { buildScanId } from "./scan-utils";
import type { ScanRecord } from "./types";

function mockJsonResponse(payload: unknown) {
  return {
    ok: true,
    status: 200,
    json: async () => payload,
    text: async () => JSON.stringify(payload),
  };
}

function buildScan(overrides: Record<string, unknown> = {}) {
  return {
    repo_url: "https://github.com/owner/repo",
    pr_url: "https://github.com/owner/repo/pull/12",
    scanned_at: "2026-03-22T12:00:00Z",
    scan_summary: {
      total_issues: 3,
      semgrep: 1,
      osv: 1,
      ai_agent: 1,
      gitleaks: 0,
      checkov: 0,
      pr_files_scanned: 4,
    },
    issues: [],
    ai_audit: {
      status: "completed",
      model: "llama-3.3-70b-versatile",
      findings: [],
    },
    gitleaks: [],
    checkov: [],
    ...overrides,
  };
}

describe("SecureAudit API client", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("posts repo_url and pr_url to analyze-pr", async () => {
    const mockFetch = vi.fn().mockResolvedValue(mockJsonResponse(buildScan()));
    vi.stubGlobal("fetch", mockFetch);

    await analyzePR(
      "https://github.com/owner/repo",
      "https://github.com/owner/repo/pull/12"
    );

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/analyze-pr");
    expect(JSON.parse(String(init.body))).toEqual({
      repo_url: "https://github.com/owner/repo",
      pr_url: "https://github.com/owner/repo/pull/12",
    });
  });

  it("loads dashboard stats from the new endpoint", async () => {
    const mockFetch = vi.fn().mockResolvedValue(
      mockJsonResponse({
        total_scans: 5,
        total_issues: 12,
      })
    );
    vi.stubGlobal("fetch", mockFetch);

    const stats = await getDashboardStats();
    expect(stats).toEqual({
      total_scans: 5,
      total_issues: 12,
    });
  });

  it("loads the saved scan dataset", async () => {
    const mockFetch = vi.fn().mockResolvedValue(
      mockJsonResponse({
        total: 1,
        scans: [buildScan()],
      })
    );
    vi.stubGlobal("fetch", mockFetch);

    const dataset = await getDataset();
    expect(dataset.total).toBe(1);
    expect(dataset.scans[0].repo_url).toBe("https://github.com/owner/repo");
  });

  it("resolves a saved scan by generated id", async () => {
    const scan = buildScan();
    const dataset = {
      total: 1,
      scans: [scan],
    };
    const mockFetch = vi.fn().mockResolvedValue(mockJsonResponse(dataset));
    vi.stubGlobal("fetch", mockFetch);

    const result = await getDataset();
    const matched = await fetchPRAnalysis(buildScanId(scan as ScanRecord));

    expect(result.scans).toHaveLength(1);
    expect(matched.pr_url).toBe("https://github.com/owner/repo/pull/12");
  });

  it("shows a friendly message when the backend is offline", async () => {
    const mockFetch = vi.fn().mockRejectedValue(new TypeError("Failed to fetch"));
    vi.stubGlobal("fetch", mockFetch);

    await expect(getDataset()).rejects.toThrow(
      "Couldn't reach the SecureAudit backend at http://127.0.0.1:8001. Make sure the FastAPI server is running."
    );
  });
});
