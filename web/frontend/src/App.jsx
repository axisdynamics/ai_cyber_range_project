// The full App is in web/frontend/dashboard_standalone.html for CDN mode.
// This file is the entry point for the Vite build — it re-exports the same App.
// In the Vite build, all components are in src/components/ and src/pages/.
// For development: `npm run dev` (proxies /api/* to FastAPI on :8080)
// For production:  `npm run build` → FastAPI serves dist/

export { default } from './components/AppShell.jsx'
