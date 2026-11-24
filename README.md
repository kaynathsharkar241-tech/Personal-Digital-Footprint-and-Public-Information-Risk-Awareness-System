# Privacy Monitor — React + Express

Privacy Monitor is a single React/TypeScript frontend with an Express/TypeScript backend and SQLite database.

## Run locally on macOS

1. Install Node.js 22 or newer.
2. Copy `.env.example` to `.env` and add the API keys you actually have.
3. Install dependencies and start the application:

```bash
cp .env.example .env
npm install
npm test
npm run lint
npm run build
npm run dev
```

Open `http://localhost:3000`.

## Real-data-only monitoring

Live findings are accepted only from external providers. No demo provider, synthetic finding generator, sample cases, or sample user is used in live application code. If a provider is not configured, fails, is rate-limited, or returns no matches, the provider status is shown honestly. See [REAL_DATA_ONLY.md](REAL_DATA_ONLY.md).

## Integrated modules

- Existing authenticated React/Express Privacy Monitor application.
- Tavily public-web search.
- Google Programmable Search (optional API key + Search Engine ID).
- Existing GitHub, Gravatar, StopForumSpam, crt.sh, RDAP/DNS, NVD, CISA KEV, Hacker News, Wikipedia, URLhaus, Brave and HIBP integrations.
- XposedOrNot public breach lookup (no API key; subject to service availability).
- Seven-question weighted digital-footprint assessment.
- Six practical digital-safety response guides.
- Existing manual guided-search links, case management, encrypted evidence, reporting, account security and scheduled monitoring.

## API configuration

The optional search providers are independent. Add only the credentials you have:

```dotenv
TAVILY_API_KEY=""
GOOGLE_API_KEY=""
GOOGLE_CSE_ID=""
BRAVE_API_KEY=""
HIBP_API_KEY=""
```

XposedOrNot is a public endpoint and does not require an API key. Missing optional credentials do not generate substitute data; those providers report `unavailable`.

## Important

- Findings are potential matches, not proof of identity. Users must review and verify them.
- Scanning should be used only for identifiers and accounts the signed-in user owns or is explicitly authorized to monitor.
- Do not replace an existing production `.env`, SQLite database, or encryption keys when updating the app.
