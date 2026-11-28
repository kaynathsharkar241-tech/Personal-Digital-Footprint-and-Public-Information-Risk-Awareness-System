# Privacy Monitor V2 — dashboard patch merge

Source: `PrivacyMonitor-V2-Review.zip`.

Changes:
- Applied `privacy-monitor-v2-dashboard.patch` without conflicts to `server/reportPdf.ts`, `src/components/DashboardView.tsx`, `src/components/MonitoringScansView.tsx`, `src/utils/findingPresentation.ts`, and `tests/finding_presentation.test.ts`.
- Restored `.env.example` and `python-ai/models/face_detection_yunet_2023mar.onnx` from `PrivacyMonitor-V2.zip`.
- Preserved all other V2-Review source files unchanged.

Validation:
- `git apply --check` succeeded before applying.
- `git apply --reverse --check` succeeded after applying.
- Automated TypeScript tests and build were NOT run because dependencies were unavailable; `npm ci --offline` failed with ENOTCACHED.

To run locally:
1. Unzip to a NEW folder; do not replace your active project or your private `.env`/SQLite data.
2. Run `npm ci` (requires access to the npm registry), `npm run lint`, `npm test`, and `npm run build`.
3. Populate `.env` from `.env.example` and use actual authorized provider credentials. Never put mock/synthetic findings in the live application.
4. Follow `README.md` / `DEPLOYMENT.md` for application run details.

This ZIP contains source code and assets only, not private database, credentials or node_modules. This is not a guarantee of production readiness.
