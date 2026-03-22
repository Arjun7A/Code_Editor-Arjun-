import axios from "axios";

const API_BASE_URL = (import.meta.env.VITE_API_URL || "http://127.0.0.1:8001").replace(/\/$/, "");

function friendlyErrorMessage(error, fallbackMessage) {
  if (error?.code === "ECONNABORTED") {
    return "The request timed out. SecureAudit scans can take 2-5 minutes, so please keep the backend running and try again.";
  }

  if (error?.response?.data?.detail) {
    return error.response.data.detail;
  }

  if (typeof error?.response?.data === "string" && error.response.data.trim()) {
    return error.response.data.trim();
  }

  if (error?.message === "Network Error") {
    return `Couldn't reach the SecureAudit backend at ${API_BASE_URL}. Make sure the FastAPI server is running.`;
  }

  return fallbackMessage;
}

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  withCredentials: false,
  headers: {
    Accept: "application/json",
    "Content-Type": "application/json",
  },
});

export const analyzePR = async (repoUrl, prUrl) => {
  try {
    const response = await api.post(
      "/analyze-pr",
      {
        repo_url: repoUrl,
        pr_url: prUrl,
      },
      {
        timeout: 330000,
      }
    );

    return response.data;
  } catch (error) {
    throw new Error(
      friendlyErrorMessage(error, "We couldn't analyze that pull request right now.")
    );
  }
};

export const getDashboardStats = async () => {
  try {
    const response = await api.get("/api/dashboard-stats");
    return response.data;
  } catch (error) {
    throw new Error(
      friendlyErrorMessage(error, "We couldn't load dashboard stats right now.")
    );
  }
};

export const getDataset = async () => {
  try {
    const response = await api.get("/dataset", {
      timeout: 60000,
    });
    return response.data;
  } catch (error) {
    throw new Error(
      friendlyErrorMessage(error, "We couldn't load saved scan results right now.")
    );
  }
};

export const predictRisk = async () => {
  throw new Error("The standalone ML prediction endpoint is not available in the new SecureAudit backend.");
};

export default api;
