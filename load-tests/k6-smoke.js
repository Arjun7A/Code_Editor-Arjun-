import http from "k6/http";
import { check, sleep } from "k6";

const BASE_URL = (__ENV.BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

export const options = {
  vus: 10,
  duration: "45s",
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<900", "avg<350"],
  },
};

function jsonHeaders() {
  return { headers: { "Content-Type": "application/json" } };
}

export default function () {
  const healthRes = http.get(`${BASE_URL}/api/health`);
  check(healthRes, {
    "health status 200": (r) => r.status === 200,
  });

  const dashboardRes = http.get(`${BASE_URL}/api/dashboard-stats`);
  check(dashboardRes, {
    "dashboard status 200": (r) => r.status === 200,
  });

  const policyRes = http.get(`${BASE_URL}/api/policy/rules`);
  check(policyRes, {
    "policy status 200": (r) => r.status === 200,
  });

  if (__ITER % 5 === 0) {
    const scanPayload = JSON.stringify({
      code: "import os\nprint('k6 smoke')\n",
      filename: "smoke.py",
    });
    const scanRes = http.post(`${BASE_URL}/api/scan`, scanPayload, jsonHeaders());
    check(scanRes, {
      "scan status 200": (r) => r.status === 200,
    });
  }

  sleep(0.5);
}
