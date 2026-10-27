// Two small local test sites for the functional tests (thesis Table 5.2).
// Start them with:  node test-site/server.js   (stop with Ctrl + C)
//
// Site A  http://127.0.0.1:4001  a normal site: 404 for missing pages, plus a test
//                                /.env file and a test key inside /app.js
// Site B  http://127.0.0.1:4002  a catch-all site: answers EVERY address with its
//                                normal page and status 200
//
// Nothing here is real. The fake values are built from pieces so that this file
// is never mistaken for a leaked secret by GitHub.
const http = require("http");

const page = (title, extra = "") =>
  `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head>` +
  `<body><h1>${title}</h1><p>A test site for the Sentinel thesis. Nothing here is real.</p>${extra}</body></html>`;

const fakeKey = "sk_" + "live_" + "TESTONLY" + "0".repeat(16);
const fakeEnv = "DB_PASSWORD=" + "test-only-not-real\n" + "API_KEY=" + "test-only-not-real\n";

const siteA = http.createServer((req, res) => {
  const path = (req.url || "/").split("?")[0];
  if (path === "/") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return res.end(page("Test site A", '<script src="/app.js"></script>'));
  }
  if (path === "/app.js") {
    res.writeHead(200, { "Content-Type": "application/javascript" });
    return res.end(`window.PAYMENT_KEY = "${fakeKey}";\n`);
  }
  if (path === "/.env") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end(fakeEnv);
  }
  if (path === "/robots.txt") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("User-agent: *\nDisallow: /admin\n");
  }
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found");
});

const siteB = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(page("Test site B (answers every address)"));
});

siteA.listen(4001, "127.0.0.1", () => console.log("Site A: http://127.0.0.1:4001"));
siteB.listen(4002, "127.0.0.1", () => console.log("Site B: http://127.0.0.1:4002"));
