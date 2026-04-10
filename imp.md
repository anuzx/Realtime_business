PulseGuard – Frontend Implementation Plan
Overview
Build the PulseGuard AI Monitor frontend — a Svelte 5 + Vite SPA dashboard. All data flows through real HTTP endpoints using the native fetch API (no axios, no mock data). Datadog-inspired dark UI with glassmorphism and micro-animations.

Existing stack: Svelte 5, Vite 8, Tailwind CSS 4, PostCSS — already scaffolded.

IMPORTANT

All HTTP calls use native fetch. An api.ts wrapper handles base URL, JWT headers, JSON parsing, and error handling.

1. Dependencies & Config
[MODIFY] 
package.json
Add: svelte-spa-router, chart.js, svelte-chartjs, lucide-svelte, clsx

[MODIFY] 
vite.config.ts
Add $lib → ./src/lib path alias + API proxy to backend (e.g. http://localhost:8000)

2. Design System
[MODIFY] 
app.css
Dark-theme CSS variables (bg, surface, border, accent purple/indigo, text)
Import Inter from Google Fonts
Glassmorphism utility classes, transition/animation globals
3. Core Utilities
[NEW] src/lib/utils.ts
cn() class-merge helper (clsx)

[NEW] src/lib/api.ts
Fetch wrapper — no axios:

ts
const BASE = '/api';
async function request(path, options) { /* fetch + auth header + JSON parse + error throw */ }
export const api = {
  login(email, password),        // POST /api/auth/login
  register(email, password),     // POST /api/auth/register
  getMe(),                       // GET  /api/users/me
  getDashboardSummary(),         // GET  /api/dashboard/summary
  getRiskScore(),                // GET  /api/dashboard/risk-score
  getLogs(filters?),             // GET  /api/logs
  getAlerts(),                   // GET  /api/alerts
  resolveAlert(id),              // PATCH /api/alerts/:id
  getApiKeys(),                  // GET  /api/api-keys
  createApiKey(name),            // POST /api/api-keys
  analyzeAI(logIds),             // POST /api/ai/analyze
};
[NEW] src/lib/stores.ts
Svelte writable stores: authStore (user + JWT token), alertsStore, logsStore

[DELETE] 
src/lib/Counter.svelte
4. UI Components
[NEW] src/lib/components/ui/ (reusable primitives)
Component	Purpose
Button.svelte	primary / secondary / ghost / danger variants
Card.svelte	glassmorphism card with header/footer slots
Input.svelte	labeled input with error state
Badge.svelte	status badges (success, warning, error, info)
Table.svelte	sortable data table
[NEW] src/lib/components/ (app-level)
Component	Purpose
Navbar.svelte	top bar: logo, nav, user menu
Sidebar.svelte	collapsible sidebar with lucide icons
DashboardLayout.svelte	sidebar + navbar + content slot
StatCard.svelte	animated stat card (icon, value, trend)
RiskGauge.svelte	circular risk score gauge
LogTable.svelte	filterable log viewer
AlertItem.svelte	alert card with severity + resolve
[NEW] src/lib/components/charts/
LineChart.svelte — request volume / response times
BarChart.svelte — errors by category
DoughnutChart.svelte — event type distribution
5. Pages
[NEW] src/lib/pages/
Page	Description	API calls
Landing.svelte	Hero, features, CTA	None
Login.svelte	Login form	api.login()
Register.svelte	Register form	api.register()
Dashboard.svelte	Stats, charts, risk gauge	api.getDashboardSummary(), api.getRiskScore()
Logs.svelte	Filterable log table	api.getLogs(filters)
Alerts.svelte	Alert list + resolve	api.getAlerts(), api.resolveAlert(id)
ApiKeys.svelte	Create + list keys	api.getApiKeys(), api.createApiKey()
Docs.svelte	Static API reference	None
Each page handles loading, error, and empty states.

6. App Shell & Router
[MODIFY] 
App.svelte
svelte-spa-router with route definitions
Public routes (Landing, Login, Register) → full-width layout
Protected routes (Dashboard, Logs, Alerts, ApiKeys, Docs) → DashboardLayout
Redirect to /login if unauthenticated
[MODIFY] 
main.ts
Clean import, mount app

Verification
npm run dev — no errors
npm run build — production build succeeds
Browser: all 8 pages render, loading/error states display correctly, dark theme + animations look premium, responsive at mobile widths
