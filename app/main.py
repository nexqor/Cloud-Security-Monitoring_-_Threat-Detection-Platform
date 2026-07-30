from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app.database import init_db
from app.api import auth, aws, dashboard, alerts, reports

app = FastAPI(
    title="CloudShield",
    description="Cloud Security Monitoring & Threat Detection Platform",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten before deploying past dev
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(aws.router)
app.include_router(dashboard.router)
app.include_router(alerts.router)
app.include_router(reports.router)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def root():
    return {"service": "cloudshield", "status": "ok", "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok", "service": "cloudshield"}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page():
    return """
    <!DOCTYPE html>
    <html lang=\"en\">
    <head>
        <meta charset=\"utf-8\">
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
        <title>CloudShield Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 2rem; background: #f7f9fc; color: #1f2937; }
            .card { background: white; border-radius: 10px; padding: 1.2rem; margin-bottom: 1rem; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
            .stats { display: flex; gap: 1rem; flex-wrap: wrap; }
            .pill { padding: 0.7rem 1rem; border-radius: 8px; background: #eff6ff; min-width: 140px; }
            code { background: #eef2ff; padding: 0.2rem 0.4rem; border-radius: 4px; }
            a { color: #2563eb; }
        </style>
    </head>
    <body>
        <h1>CloudShield Dashboard</h1>
        <div class=\"card\">
            <p>Open the API docs at <a href=\"/docs\">/docs</a> to register, log in, and run scans.</p>
            <div id=\"status\">Loading summary...</div>
        </div>
        <div class=\"card\">
            <h2>Security Overview</h2>
            <div class=\"stats\">
                <div class=\"pill\"><strong>Security Score</strong><br/><span id=\"score\">--</span></div>
                <div class=\"pill\"><strong>Open Findings</strong><br/><span id=\"open\">--</span></div>
                <div class=\"pill\"><strong>Critical</strong><br/><span id=\"critical\">--</span></div>
                <div class=\"pill\"><strong>High</strong><br/><span id=\"high\">--</span></div>
            </div>
        </div>
        <div class=\"card\">
            <h2>Login</h2>
            <form id=\"loginForm\">
                <input id=\"username\" placeholder=\"Username\" required />
                <input id=\"password\" type=\"password\" placeholder=\"Password\" required />
                <button type=\"submit\">Log In</button>
            </form>
            <p id=\"authStatus\">Not logged in.</p>
        </div>
        <div class=\"card\">
            <h2>Quick Actions</h2>
            <p>These actions require a valid authentication token from the API.</p>
            <button id=\"scanBtn\">Run Scan</button>
            <p id=\"scanStatus\">No scan run yet.</p>
        </div>
        <div class=\"card\">
            <h2>Recent Findings</h2>
            <ul id=\"findingsList\"><li>Loading findings...</li></ul>
        </div>
        <div class=\"card\">
            <h2>How to use this page</h2>
            <ol>
                <li>Create a user with <code>POST /api/auth/register</code></li>
                <li>Log in with <code>POST /api/auth/login</code></li>
                <li>Copy the returned token and use it as a bearer token on protected routes</li>
            </ol>
        </div>
        <script>
            let authToken = '';

            async function fetchWithAuth(url, options = {}) {
                const headers = options.headers || {};
                if (authToken) {
                    headers['Authorization'] = `Bearer ${authToken}`;
                }
                return fetch(url, { ...options, headers });
            }

            async function loadSummary() {
                try {
                    const response = await fetchWithAuth('/api/dashboard/summary');
                    if (!response.ok) {
                        document.getElementById('status').innerHTML = 'Summary unavailable. Register and log in first.';
                        return;
                    }
                    const data = await response.json();
                    document.getElementById('status').innerHTML = 'Summary loaded successfully.';
                    document.getElementById('score').textContent = data.security_score ?? '--';
                    document.getElementById('open').textContent = data.open_findings ?? '--';
                    document.getElementById('critical').textContent = data.findings_by_severity?.CRITICAL ?? 0;
                    document.getElementById('high').textContent = data.findings_by_severity?.HIGH ?? 0;
                } catch (err) {
                    document.getElementById('status').innerHTML = 'Summary unavailable. The API may require authentication.';
                }
            }

            async function loadFindings() {
                try {
                    const response = await fetchWithAuth('/api/alerts/findings');
                    if (!response.ok) {
                        document.getElementById('findingsList').innerHTML = '<li>Findings unavailable until you log in.</li>';
                        return;
                    }
                    const data = await response.json();
                    if (!data.length) {
                        document.getElementById('findingsList').innerHTML = '<li>No findings yet.</li>';
                        return;
                    }
                    document.getElementById('findingsList').innerHTML = data.slice(0, 6).map(item => `
                        <li><strong>${item.title}</strong> — ${item.severity} (${item.status})</li>
                    `).join('');
                } catch (err) {
                    document.getElementById('findingsList').innerHTML = '<li>Findings unavailable until you log in.</li>';
                }
            }

            document.getElementById('loginForm').addEventListener('submit', async (event) => {
                event.preventDefault();
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                document.getElementById('authStatus').textContent = 'Logging in...';
                try {
                    const formData = new URLSearchParams();
                    formData.append('username', username);
                    formData.append('password', password);
                    const response = await fetch('/api/auth/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: formData.toString()
                    });
                    const data = await response.json();
                    if (!response.ok) {
                        document.getElementById('authStatus').textContent = 'Login failed.';
                        return;
                    }
                    authToken = data.access_token;
                    document.getElementById('authStatus').textContent = 'Logged in successfully.';
                    loadSummary();
                    loadFindings();
                } catch (err) {
                    document.getElementById('authStatus').textContent = 'Login failed.';
                }
            });

            document.getElementById('scanBtn').addEventListener('click', async () => {
                document.getElementById('scanStatus').textContent = 'Starting scan...';
                try {
                    const response = await fetchWithAuth('/api/dashboard/scan', { method: 'POST' });
                    if (!response.ok) {
                        document.getElementById('scanStatus').textContent = 'Scan requires authentication.';
                        return;
                    }
                    const data = await response.json();
                    document.getElementById('scanStatus').textContent = `Scan started: ${data.scan_id} (${data.status})`;
                    setTimeout(() => {
                        loadSummary();
                        loadFindings();
                    }, 1000);
                } catch (err) {
                    document.getElementById('scanStatus').textContent = 'Scan failed.';
                }
            });

            loadSummary();
            loadFindings();
        </script>
    </body>
    </html>
    """
