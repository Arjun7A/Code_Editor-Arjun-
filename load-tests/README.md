# Load Testing

This folder contains k6 scripts for backend performance validation.

## Scripts
- `k6-smoke.js`: short smoke profile to validate endpoint health under light concurrency.
- `k6-stress.js`: ramped stress profile for dashboard/results/policy traffic.

## Run Locally

1. Start backend (`http://127.0.0.1:8000` by default).
2. Run with local k6 install:

```bash
k6 run load-tests/k6-smoke.js
k6 run load-tests/k6-stress.js
```

3. Or run with Docker (no local install required):

```bash
docker run --rm -i -v ${PWD}:/work -w /work grafana/k6 run load-tests/k6-smoke.js
docker run --rm -i -v ${PWD}:/work -w /work grafana/k6 run load-tests/k6-stress.js
```

## Custom Target URL

```bash
k6 run -e BASE_URL=https://your-api.onrender.com load-tests/k6-smoke.js
```
