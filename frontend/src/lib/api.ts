import type {
  DatasetResponse,
  RawDashboardStats,
  ScanRecord,
} from "./types";
import { buildScanId } from "./scan-utils";

const API_BASE_URL = (import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8001").replace(/\/$/, "");

type RequestOptions = RequestInit & {
  timeoutMs?: number;
};

function toFriendlyMessage(error: unknown, fallback: string): string {
  if (error instanceof DOMException && error.name === "AbortError") {
    return "The request took too long. The backend scan can take 2-5 minutes, so please try again once the server is ready.";
  }

  if (error instanceof TypeError) {
    return `Couldn't reach the SecureAudit backend at ${API_BASE_URL}. Make sure the FastAPI server is running.`;
  }

  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }

  return fallback;
}

async function requestJson<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { timeoutMs = 30000, headers, ...init } = options;
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      mode: "cors",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        ...headers,
      },
      ...init,
      signal: controller.signal,
    });

    if (!response.ok) {
      let message = `Request failed with status ${response.status}.`;

      try {
        const payload = await response.json();
        if (typeof payload?.detail === "string") {
          message = payload.detail;
        }
      } catch {
        const text = await response.text().catch(() => "");
        if (text.trim()) {
          message = text.trim();
        }
      }

      throw new Error(message);
    }

    return response.json() as Promise<T>;
  } catch (error) {
    throw new Error(toFriendlyMessage(error, "Something went wrong while talking to the backend."));
  } finally {
    globalThis.clearTimeout(timeout);
  }
}

export async function analyzePR(repoUrl: string, prUrl: string): Promise<ScanRecord> {
  return requestJson<ScanRecord>("/analyze-pr", {
    method: "POST",
    body: JSON.stringify({
      repo_url: repoUrl,
      pr_url: prUrl,
    }),
    timeoutMs: 330000,
  });
}

export async function getDashboardStats(): Promise<RawDashboardStats> {
  return requestJson<RawDashboardStats>("/api/dashboard-stats");
}

export async function getDataset(): Promise<DatasetResponse> {
  return requestJson<DatasetResponse>("/dataset", {
    timeoutMs: 60000,
  });
}

export async function fetchPRAnalysis(id: string): Promise<ScanRecord> {
  const dataset = await getDataset();
  const match = dataset.scans.find((scan) => buildScanId(scan) === id);

  if (!match) {
    throw new Error("We couldn't find that saved scan in the dataset.");
  }

  return match;
}
