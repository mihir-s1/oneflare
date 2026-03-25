// Generates a large synthetic customer dataset for exfil simulation
function generateCustomers(count = 500) {
  const firstNames = ["James","Mary","John","Patricia","Robert","Jennifer","Michael","Linda","William","Barbara","David","Susan","Richard","Jessica","Joseph","Sarah","Thomas","Karen","Charles","Lisa"];
  const lastNames = ["Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis","Rodriguez","Martinez","Hernandez","Lopez","Gonzalez","Wilson","Anderson","Thomas","Taylor","Moore","Jackson","Martin"];
  const domains = ["gmail.com","yahoo.com","outlook.com","acmecorp.com","hotmail.com"];
  const states = ["CA","NY","TX","FL","IL","PA","OH","GA","NC","MI"];

  return Array.from({ length: count }, (_, i) => {
    const first = firstNames[i % firstNames.length];
    const last = lastNames[Math.floor(i / firstNames.length) % lastNames.length];
    return {
      id: 10000 + i,
      first_name: first,
      last_name: last,
      email: `${first.toLowerCase()}.${last.toLowerCase()}${i}@${domains[i % domains.length]}`,
      phone: `+1-${String(200 + (i % 800)).padStart(3,"0")}-555-${String(1000 + i).slice(-4)}`,
      address: `${100 + i} Main St`,
      city: ["New York","Los Angeles","Chicago","Houston","Phoenix"][i % 5],
      state: states[i % states.length],
      zip: String(10000 + (i * 7) % 89999).padStart(5,"0"),
      created_at: new Date(Date.now() - (i * 86400000)).toISOString(),
      total_orders: Math.floor(Math.random() * 50),
      lifetime_value: parseFloat((Math.random() * 5000).toFixed(2)),
      card_last4: String(1000 + (i * 13) % 8999),
      card_type: ["Visa","Mastercard","Amex"][i % 3],
    };
  });
}

const ALL_CUSTOMERS = generateCustomers(500);

const MOCK_TOKEN = "mock-jwt-token-abc123";

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      "X-API-Version": "v1",
      "X-Content-Type-Options": "nosniff",
    }
  });
}

// LAB NOTE: wildcard CORS is intentional — the export endpoint is a data exfil target.
// Attack scripts POST from arbitrary origins. Do not restrict for lab use.
function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

function requireAuth(request) {
  const auth = request.headers.get("Authorization") || "";
  if (auth !== `Bearer ${MOCK_TOKEN}`) {
    return jsonResponse({ success: false, error: "Unauthorized" }, 401);
  }
  return null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    // Health check
    if (path === "/" || path === "/api/v1/health") {
      return jsonResponse({
        status: "healthy",
        version: "1.4.2",
        timestamp: new Date().toISOString(),
        services: { database: "ok", cache: "ok", queue: "ok" }
      });
    }

    // Auth
    // LAB NOTE: credentials are configurable via Wrangler secrets.
    // Set via: wrangler secret put API_USERNAME / wrangler secret put API_PASSWORD
    if (path === "/api/v1/auth/login" && method === "POST") {
      const body = await request.json().catch(() => ({}));
      const { username, password } = body;
      if (!username || !password) {
        return jsonResponse({ success: false, error: "Missing credentials" }, 400);
      }
      const validUser = env.API_USERNAME || "api_user@acmecorp.com";
      const validPass = env.API_PASSWORD || "ApiUser2026!";
      if (username === validUser && password === validPass) {
        return jsonResponse({ success: true, token: MOCK_TOKEN, expires_in: 3600 });
      }
      return jsonResponse({ success: false, error: "Invalid credentials" }, 401);
    }

    // List customers (paginated) — requires auth token
    if (path === "/api/v1/customers" && method === "GET") {
      const authErr = requireAuth(request);
      if (authErr) return authErr;
      const page = parseInt(url.searchParams.get("page") || "1");
      const limit = Math.min(parseInt(url.searchParams.get("limit") || "20"), 100);
      const offset = (page - 1) * limit;
      const customers = ALL_CUSTOMERS.slice(offset, offset + limit);
      return jsonResponse({
        success: true,
        page,
        limit,
        total: ALL_CUSTOMERS.length,
        total_pages: Math.ceil(ALL_CUSTOMERS.length / limit),
        data: customers
      });
    }

    // Export — intentional data exfiltration target for attack simulation
    // LAB NOTE: auth check is intentionally weak — attack scripts obtain the token
    // via credential stuffing on /auth/login, then bulk-pull here to generate exfil logs.
    if (path === "/api/v1/customers/export" && method === "GET") {
      const authErr = requireAuth(request);
      if (authErr) return authErr;
      const format = url.searchParams.get("format") || "json";
      if (format === "csv") {
        const headers = Object.keys(ALL_CUSTOMERS[0]).join(",");
        const rows = ALL_CUSTOMERS.map(c => Object.values(c).map(v => `"${v}"`).join(","));
        const csv = [headers, ...rows].join("\n");
        return new Response(csv, {
          headers: {
            "Content-Type": "text/csv",
            "Content-Disposition": 'attachment; filename="customers_export.csv"',
            "X-Record-Count": String(ALL_CUSTOMERS.length),
          }
        });
      }
      return jsonResponse({
        success: true,
        exported_at: new Date().toISOString(),
        record_count: ALL_CUSTOMERS.length,
        data: ALL_CUSTOMERS
      });
    }

    // Single customer
    if (path.match(/^\/api\/v1\/customers\/\d+$/) && method === "GET") {
      const id = parseInt(path.split("/")[4]);
      const customer = ALL_CUSTOMERS.find(c => c.id === id);
      if (!customer) return jsonResponse({ success: false, error: "Customer not found" }, 404);
      return jsonResponse({ success: true, data: customer });
    }

    // Orders
    if (path === "/api/v1/orders" && method === "GET") {
      const orders = Array.from({ length: 25 }, (_, i) => ({
        id: `ORD-${10000 + i}`,
        customer_id: 10000 + (i * 7 % 500),
        status: ["pending","processing","shipped","delivered","cancelled"][i % 5],
        total: parseFloat((50 + Math.random() * 450).toFixed(2)),
        items: Math.floor(1 + Math.random() * 8),
        created_at: new Date(Date.now() - i * 3600000).toISOString(),
      }));
      return jsonResponse({ success: true, total: orders.length, data: orders });
    }

    return jsonResponse({ success: false, error: "Not found" }, 404);
  }
};
