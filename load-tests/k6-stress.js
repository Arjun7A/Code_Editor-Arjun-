import http from "k6/http";
import { check, sleep } from "k6";

const BASE_URL = (__ENV.BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

export const options = {
  stages: [
    { duration: "30s", target: 25 },
    { duration: "45s", target: 60 },
    { duration: "30s", target: 90 },
    { duration: "20s", target: 0 },
  ],
  thresholds: {
    http_req_failed: ["rate<0.03"],
    http_req_duration: ["p(95)<1500", "p(99)<2500"],
  },
};

function getResultsLimit() {
  const limits = [10, 20, 30, 40, 50];
  return limits[__ITER % limits.length];
}

export default function () {
  const requests = [
    ["GET", `${BASE_URL}/api/health`, null],
    ["GET", `${BASE_URL}/api/dashboard-stats`, null],
    ["GET", `${BASE_URL}/api/results?skip=0&limit=${getResultsLimit()}`, null],
    ["GET", `${BASE_URL}/api/policy/rules`, null],
  ];

  const responses = http.batch(requests);

  check(responses[0], { "health 200": (r) => r.status === 200 });
  check(responses[1], { "dashboard 200": (r) => r.status === 200 });
  check(responses[2], { "results 200": (r) => r.status === 200 });
  check(responses[3], { "policy 200": (r) => r.status === 200 });

  sleep(0.4);
}
