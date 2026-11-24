# Integration notes

## `Projec.zip` integrated
- The seven weighted questions and their 0/1/2 risk values are now served by the Express API and saved in the existing SQLite `answers` table.
- Question IDs 101–107 avoid accidentally interpreting older five-question answers as answers to the new assessment.
- The six practical response guides are rendered inside the existing Questionnaire & Guides screen.
- Existing guided Google/DuckDuckGo manual-search links remain part of the same screen.
- The standalone HTML/CSS/JavaScript pages were not copied as a second website; their functionality is integrated into the existing React application.

## `privacy-monitor-scanning.zip` integrated
- Added Google Programmable Search as an optional real provider (`GOOGLE_API_KEY` + `GOOGLE_CSE_ID`).
- Added XposedOrNot as a real public breach lookup provider for the user's monitored email.
- The existing React application's manual and scheduled scan workers, result de-duplication, risk assessment, notifications, and provider telemetry are retained.
- The Flask application itself was not copied or run alongside Express. This avoids creating a second app, a second user database, and a separate unauthenticated scanning surface.

## Explicitly excluded to satisfy real-data-only
- `DemoSearch` and `DemoBreach`.
- `SAMPLE_CASES`, default sample user records, and fabricated example URLs/findings.
- Any fallback that turns a missing API key or failed request into a finding.
- The uploaded Flask test's assertion that a no-key demo scan must create findings.

Automated tests may contain isolated test fixtures. They must not seed live accounts or be presented as real scan results.
