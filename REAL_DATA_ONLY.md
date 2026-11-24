# Real-data-only operation

Privacy Monitor must never fabricate, synthesize, simulate, or randomly generate monitoring findings for live users.

## Live monitoring rules
- Findings may be created only from responses returned by configured external OSINT providers.
- An empty provider response means zero findings from that provider; it must not be replaced with sample records.
- A provider that is missing credentials, rate-limited, unreachable, or returns an error must be marked skipped/unavailable/error in the provider summary.
- A partial scan must be labelled as partial coverage. It must not be described as a clean scan.
- Risk scores and reports must be based on actual retrieved findings and must clearly distinguish unverified potential matches from user-confirmed matches.
- Cached provider responses are previously retrieved real responses and must retain their source and retrieval metadata.
- Automated test fixtures are permitted only inside isolated automated tests; they must never be written into the live user database or displayed as real findings.

## Existing implementation evidence
The supplied React/Express source includes live OSINT provider adapters, provider status reporting, and a database migration that deletes legacy rows marked synthetic and legacy scans with mode `synthetic`. The monitoring UI also explains unavailable and skipped providers rather than treating them as clean matches.

## Important verification note
This package is based on the supplied `privacy-monitor (1).zip` source snapshot. That snapshot did not contain a Tavily provider implementation or `TAVILY_API_KEY` entry in `.env.example`, despite Tavily being present in earlier terminal output shared in the conversation. Confirm that the latest Tavily implementation is present in your working copy before replacing it with this package. Do not assume this archive includes that later local change.

## Integrated source projects
- `Projec.zip`: its seven-question weighted digital-footprint self-assessment and six practical response guides are integrated into the existing React questionnaire area.
- `privacy-monitor-scanning.zip`: its live-source scanning approach has been incorporated as optional Google Programmable Search and public XposedOrNot breach lookup providers. Existing Tavily and other providers remain in the React/Express provider registry.
- The Flask application's DemoSearch, DemoBreach, sample user, sample cases, and `is_demo` result path were intentionally not imported. They create fabricated demonstration data and conflict with the real-data-only requirement.
- No static example findings or sample cases are seeded into live user accounts. Static educational guidance is informational content, not scan output.
