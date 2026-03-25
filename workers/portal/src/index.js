const STYLES = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
  .login-wrapper { display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 24px; }
  .login-card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 40px; width: 100%; max-width: 400px; }
  .logo { text-align: center; margin-bottom: 32px; }
  .logo h1 { font-size: 22px; color: #38bdf8; letter-spacing: 2px; }
  .logo p { font-size: 12px; color: #64748b; margin-top: 4px; letter-spacing: 1px; text-transform: uppercase; }
  .form-group { margin-bottom: 18px; }
  .form-group label { display: block; font-size: 12px; color: #94a3b8; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
  .form-group input { width: 100%; padding: 10px 14px; background: #0f172a; border: 1px solid #334155; border-radius: 6px; color: #e2e8f0; font-size: 14px; }
  .form-group input:focus { outline: none; border-color: #38bdf8; }
  .btn-primary { width: 100%; padding: 12px; background: #38bdf8; color: #0f172a; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: bold; letter-spacing: 0.5px; margin-top: 8px; }
  .btn-primary:hover { background: #7dd3fc; }
  .error-msg { background: #450a0a; border: 1px solid #7f1d1d; color: #fca5a5; padding: 10px 14px; border-radius: 6px; font-size: 13px; margin-bottom: 16px; }
  .sso-divider { text-align: center; color: #475569; font-size: 12px; margin: 20px 0; }
  .btn-sso { width: 100%; padding: 10px; background: transparent; border: 1px solid #334155; border-radius: 6px; color: #94a3b8; cursor: pointer; font-size: 13px; }
  .footer-note { text-align: center; font-size: 11px; color: #475569; margin-top: 24px; }

  /* Dashboard */
  .app { display: flex; min-height: 100vh; }
  .sidebar { width: 220px; background: #1e293b; border-right: 1px solid #334155; padding: 24px 0; flex-shrink: 0; }
  .sidebar .brand { padding: 0 20px 24px; border-bottom: 1px solid #334155; }
  .sidebar .brand h2 { font-size: 16px; color: #38bdf8; }
  .sidebar .brand p { font-size: 11px; color: #64748b; margin-top: 2px; }
  .sidebar nav { padding: 16px 0; }
  .sidebar nav a { display: block; padding: 10px 20px; color: #94a3b8; text-decoration: none; font-size: 13px; }
  .sidebar nav a:hover, .sidebar nav a.active { background: #0f172a; color: #e2e8f0; border-left: 3px solid #38bdf8; }
  .main { flex: 1; padding: 32px; overflow-y: auto; }
  .page-header { margin-bottom: 28px; }
  .page-header h1 { font-size: 22px; color: #f1f5f9; }
  .page-header p { font-size: 13px; color: #64748b; margin-top: 4px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .stat-card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; }
  .stat-card .label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }
  .stat-card .value { font-size: 28px; font-weight: bold; color: #f1f5f9; margin-top: 6px; }
  .stat-card .sub { font-size: 12px; color: #38bdf8; margin-top: 4px; }
  .table-card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; overflow: hidden; }
  .table-card h3 { padding: 16px 20px; font-size: 14px; border-bottom: 1px solid #334155; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 12px 20px; font-size: 13px; text-align: left; }
  th { color: #64748b; font-weight: 500; font-size: 11px; text-transform: uppercase; border-bottom: 1px solid #334155; }
  td { color: #cbd5e1; border-bottom: 1px solid #1e293b; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 11px; }
  .badge-green { background: #052e16; color: #4ade80; }
  .badge-yellow { background: #422006; color: #fbbf24; }
  .badge-red { background: #450a0a; color: #f87171; }
`;

function loginPage(error = "") {
  return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AcmeCorp — Employee Portal</title>
  <style>${STYLES}</style>
</head>
<body>
  <div class="login-wrapper">
    <div class="login-card">
      <div class="logo">
        <h1>ACMECORP</h1>
        <p>Employee Portal</p>
      </div>
      ${error ? `<div class="error-msg">${error}</div>` : ""}
      <form method="POST" action="/login">
        <div class="form-group">
          <label>Corporate Email</label>
          <input type="text" name="username" placeholder="you@acmecorp.com" autocomplete="username" />
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" name="password" placeholder="••••••••" autocomplete="current-password" />
        </div>
        <button class="btn-primary" type="submit">Sign In</button>
      </form>
      <div class="sso-divider">or</div>
      <button class="btn-sso">Continue with SSO</button>
      <div class="footer-note">AcmeCorp IT — <a href="#" style="color:#38bdf8;">Need help?</a></div>
    </div>
  </div>
</body>
</html>`, { headers: { "Content-Type": "text/html" } });
}

function dashboardPage(user = "employee@acmecorp.com") {
  return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Dashboard — AcmeCorp Portal</title>
  <style>${STYLES}</style>
</head>
<body>
  <div class="app">
    <div class="sidebar">
      <div class="brand">
        <h2>ACMECORP</h2>
        <p>Employee Portal</p>
      </div>
      <nav>
        <a href="/dashboard" class="active">Dashboard</a>
        <a href="/dashboard/profile">My Profile</a>
        <a href="/dashboard/directory">Directory</a>
        <a href="/dashboard/it">IT Requests</a>
        <a href="/dashboard/payroll">Payroll</a>
        <a href="/logout">Sign Out</a>
      </nav>
    </div>
    <div class="main">
      <div class="page-header">
        <h1>Welcome back</h1>
        <p>Signed in as ${user} · Last login: today at 09:14 AM from 198.51.100.1</p>
      </div>
      <div class="cards">
        <div class="stat-card">
          <div class="label">Open IT Tickets</div>
          <div class="value">3</div>
          <div class="sub">1 urgent</div>
        </div>
        <div class="stat-card">
          <div class="label">Pending Approvals</div>
          <div class="value">7</div>
          <div class="sub">Due this week</div>
        </div>
        <div class="stat-card">
          <div class="label">Team Members</div>
          <div class="value">24</div>
          <div class="sub">3 new this month</div>
        </div>
        <div class="stat-card">
          <div class="label">Days to Review</div>
          <div class="value">14</div>
          <div class="sub">Performance cycle</div>
        </div>
      </div>
      <div class="table-card">
        <h3>Recent Activity</h3>
        <table>
          <thead>
            <tr><th>Event</th><th>User</th><th>Time</th><th>Status</th></tr>
          </thead>
          <tbody>
            <tr><td>VPN access granted</td><td>j.smith@acmecorp.com</td><td>10 min ago</td><td><span class="badge badge-green">OK</span></td></tr>
            <tr><td>Login from new device</td><td>m.jones@acmecorp.com</td><td>1 hr ago</td><td><span class="badge badge-yellow">Review</span></td></tr>
            <tr><td>Password reset</td><td>a.lee@acmecorp.com</td><td>2 hrs ago</td><td><span class="badge badge-green">OK</span></td></tr>
            <tr><td>Failed login (×5)</td><td>r.chen@acmecorp.com</td><td>3 hrs ago</td><td><span class="badge badge-red">Alert</span></td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</body>
</html>`, { headers: { "Content-Type": "text/html" } });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Root → redirect to login
    if (path === "/" || path === "") {
      return Response.redirect(new URL("/login", request.url), 302);
    }

    // Login GET
    if (path === "/login" && method === "GET") {
      return loginPage();
    }

    // Login POST — credential stuffing / brute force target
    if (path === "/login" && method === "POST") {
      const body = await request.text();
      const params = new URLSearchParams(body);
      const username = params.get("username") || "";
      const password = params.get("password") || "";

      if (!username || !password) {
        return new Response(JSON.stringify({ success: false, error: "Missing credentials" }),
          { status: 400, headers: { "Content-Type": "application/json" } });
      }

      // LAB NOTE: credentials are intentionally configurable via Wrangler secrets.
      // Set via: wrangler secret put PORTAL_USERNAME / wrangler secret put PORTAL_PASSWORD
      // Default fallback is used only if secrets are not configured (local dev).
      const validUser = env.PORTAL_USERNAME || "admin@acmecorp.com";
      const validPass = env.PORTAL_PASSWORD || "AcmeAdmin2026!";
      if (username === validUser && password === validPass) {
        return Response.redirect(new URL("/dashboard", request.url), 302);
      }

      return new Response(JSON.stringify({ success: false, error: "Invalid email or password" }),
        { status: 401, headers: { "Content-Type": "application/json" } });
    }

    // Dashboard and sub-pages
    if (path.startsWith("/dashboard")) {
      return dashboardPage();
    }

    if (path === "/logout") {
      return Response.redirect(new URL("/login", request.url), 302);
    }

    return new Response("Not found", { status: 404 });
  }
};
