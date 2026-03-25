const PRODUCTS = [
  { id: 1, name: "Wireless Headphones", price: 79.99, category: "electronics", stock: 42 },
  { id: 2, name: "Running Shoes", price: 129.99, category: "footwear", stock: 15 },
  { id: 3, name: "Coffee Maker", price: 49.99, category: "appliances", stock: 8 },
  { id: 4, name: "Yoga Mat", price: 29.99, category: "fitness", stock: 30 },
  { id: 5, name: "Laptop Stand", price: 39.99, category: "electronics", stock: 22 },
  { id: 6, name: "Water Bottle", price: 19.99, category: "fitness", stock: 60 },
  { id: 7, name: "Desk Lamp", price: 34.99, category: "home", stock: 18 },
  { id: 8, name: "Backpack", price: 59.99, category: "accessories", stock: 25 },
];

const STYLES = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; color: #333; }
  header { background: #1a1a2e; color: white; padding: 16px 32px; display: flex; align-items: center; justify-content: space-between; }
  header h1 { font-size: 22px; letter-spacing: 1px; }
  header nav a { color: #ccc; text-decoration: none; margin-left: 20px; font-size: 14px; }
  header nav a:hover { color: white; }
  .container { max-width: 1100px; margin: 0 auto; padding: 32px 16px; }
  .search-bar { display: flex; gap: 8px; margin-bottom: 32px; }
  .search-bar input { flex: 1; padding: 10px 16px; border: 1px solid #ddd; border-radius: 6px; font-size: 15px; }
  .search-bar button { padding: 10px 24px; background: #e94560; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 15px; }
  .products { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 20px; }
  .product-card { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.07); }
  .product-card h3 { font-size: 15px; margin-bottom: 8px; }
  .product-card .price { color: #e94560; font-weight: bold; font-size: 18px; margin-bottom: 8px; }
  .product-card .stock { font-size: 12px; color: #888; margin-bottom: 12px; }
  .product-card button { width: 100%; padding: 8px; background: #1a1a2e; color: white; border: none; border-radius: 6px; cursor: pointer; }
  .form-card { background: white; border-radius: 10px; padding: 32px; max-width: 420px; margin: 40px auto; box-shadow: 0 2px 12px rgba(0,0,0,0.1); }
  .form-card h2 { margin-bottom: 24px; }
  .form-group { margin-bottom: 16px; }
  .form-group label { display: block; font-size: 13px; color: #666; margin-bottom: 6px; }
  .form-group input, .form-group textarea { width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; }
  .btn-primary { width: 100%; padding: 12px; background: #e94560; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 15px; font-weight: bold; }
  .alert { padding: 12px 16px; border-radius: 6px; margin-bottom: 16px; font-size: 14px; }
  .alert-info { background: #e8f4fd; border: 1px solid #bee3f8; color: #2c5282; }
  .search-results-header { margin-bottom: 16px; font-size: 14px; color: #666; }
  footer { text-align: center; padding: 32px; color: #999; font-size: 13px; margin-top: 60px; border-top: 1px solid #eee; }
`;

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  // LAB NOTE: CSP intentionally permits inline scripts/styles — this is a WAF test target.
  // The search endpoint reflects ?q= unsanitized (intentional XSS surface for WAF testing).
  "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
};

function html(title, body) {
  return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} — AcmeShop</title>
  <style>${STYLES}</style>
</head>
<body>
  <header>
    <h1>ACMESHOP</h1>
    <nav>
      <a href="/">Home</a>
      <a href="/search">Browse</a>
      <a href="/cart">Cart (0)</a>
      <a href="/login">Login</a>
    </nav>
  </header>
  ${body}
  <footer>© 2026 AcmeShop Inc. All rights reserved.</footer>
</body>
</html>`, { headers: { "Content-Type": "text/html", ...SECURITY_HEADERS } });
}

function productGrid(products) {
  if (products.length === 0) return `<p style="color:#888;">No products found.</p>`;
  return `<div class="products">${products.map(p => `
    <div class="product-card">
      <h3>${p.name}</h3>
      <div class="price">$${p.price}</div>
      <div class="stock">${p.stock > 0 ? `${p.stock} in stock` : "Out of stock"}</div>
      <button onclick="alert('Added to cart!')">Add to Cart</button>
    </div>`).join("")}</div>`;
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Homepage
    if (path === "/" || path === "") {
      return html("Home", `
        <div class="container">
          <div class="search-bar">
            <input type="text" id="q" placeholder="Search products..." />
            <button onclick="window.location='/search?q='+document.getElementById('q').value">Search</button>
          </div>
          <h2 style="margin-bottom:20px;">Featured Products</h2>
          ${productGrid(PRODUCTS)}
        </div>`);
    }

    // Search — primary WAF/SQLi target
    if (path === "/search") {
      const q = url.searchParams.get("q") || "";
      const results = q
        ? PRODUCTS.filter(p =>
            p.name.toLowerCase().includes(q.toLowerCase()) ||
            p.category.toLowerCase().includes(q.toLowerCase()))
        : PRODUCTS;
      return html("Search", `
        <div class="container">
          <div class="search-bar">
            <input type="text" value="${q}" id="q" placeholder="Search products..." />
            <button onclick="window.location='/search?q='+document.getElementById('q').value">Search</button>
          </div>
          <div class="search-results-header">
            ${q ? `Showing results for: <strong>${q}</strong> — ${results.length} found` : `All products — ${results.length} items`}
          </div>
          ${productGrid(results)}
        </div>`);
    }

    // Login — credential stuffing target
    if (path === "/login") {
      if (method === "POST") {
        const body = await request.text();
        const params = new URLSearchParams(body);
        const username = params.get("username") || "";
        const password = params.get("password") || "";
        // Always reject — we don't have real auth, just generate logs
        if (!username || !password) {
          return new Response(JSON.stringify({ success: false, error: "Missing credentials" }),
            { status: 400, headers: { "Content-Type": "application/json" } });
        }
        return new Response(JSON.stringify({ success: false, error: "Invalid username or password" }),
          { status: 401, headers: { "Content-Type": "application/json" } });
      }
      return html("Login", `
        <div class="container">
          <div class="form-card">
            <h2>Sign In</h2>
            <form method="POST" action="/login">
              <div class="form-group">
                <label>Email address</label>
                <input type="text" name="username" placeholder="you@example.com" />
              </div>
              <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="••••••••" />
              </div>
              <button class="btn-primary" type="submit">Sign In</button>
            </form>
          </div>
        </div>`);
    }

    // Product detail — path traversal target
    if (path.startsWith("/products/")) {
      const id = parseInt(path.split("/")[2]);
      const product = PRODUCTS.find(p => p.id === id);
      if (!product) {
        return new Response("Product not found", { status: 404 });
      }
      return html(product.name, `
        <div class="container">
          <div class="form-card" style="max-width:600px;">
            <h2>${product.name}</h2>
            <p style="font-size:28px;color:#e94560;font-weight:bold;margin:16px 0;">$${product.price}</p>
            <p style="color:#888;margin-bottom:24px;">Category: ${product.category} — ${product.stock} in stock</p>
            <button class="btn-primary">Add to Cart</button>
            <hr style="margin:32px 0;">
            <h3 style="margin-bottom:16px;">Leave a Review</h3>
            <form method="POST" action="/reviews">
              <input type="hidden" name="product_id" value="${product.id}" />
              <div class="form-group">
                <label>Your review</label>
                <textarea name="review" rows="3" placeholder="Write your review here..."></textarea>
              </div>
              <button class="btn-primary" type="submit">Submit Review</button>
            </form>
          </div>
        </div>`);
    }

    // Reviews — XSS target
    if (path === "/reviews" && method === "POST") {
      return new Response(JSON.stringify({ success: true, message: "Review submitted" }),
        { headers: { "Content-Type": "application/json" } });
    }

    // Checkout
    if (path === "/checkout") {
      return html("Checkout", `
        <div class="container">
          <div class="form-card">
            <h2>Checkout</h2>
            <div class="alert alert-info">Your cart has 1 item.</div>
            <form method="POST" action="/checkout">
              <div class="form-group">
                <label>Card number</label>
                <input type="text" name="card_number" placeholder="1234 5678 9012 3456" />
              </div>
              <div class="form-group">
                <label>Cardholder name</label>
                <input type="text" name="name" placeholder="Jane Smith" />
              </div>
              <div class="form-group">
                <label>Expiry</label>
                <input type="text" name="expiry" placeholder="MM/YY" />
              </div>
              <button class="btn-primary" type="submit">Place Order</button>
            </form>
          </div>
        </div>`);
    }

    if (path === "/cart") {
      return html("Cart", `<div class="container"><p style="padding:40px 0;color:#888;">Your cart is empty.</p></div>`);
    }

    return new Response("Not found", { status: 404 });
  }
};
