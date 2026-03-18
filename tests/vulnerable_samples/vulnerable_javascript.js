/**
 * VULNERABLE JAVASCRIPT SAMPLE — FOR SECURITY SCANNER TESTING ONLY
 * Each section intentionally contains a common vulnerability.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */

const express = require("express");
const { exec } = require("child_process");
const mysql = require("mysql2");
const path = require("path");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const db = mysql.createConnection({ host: "localhost", user: "root", database: "app" });

// ── VULNERABILITY 1: Hardcoded API Key / Secret (CWE-798, A02) ──────────────
// BAD: Credentials committed to source control
const API_KEY = "sk-prod-abcdef1234567890deadbeef";          // VULNERABLE
const JWT_SECRET = "my_super_secret_jwt_key_do_not_share";   // VULNERABLE
const DB_PASSWORD = "admin123!";                              // VULNERABLE


// ── VULNERABILITY 2: SQL Injection (CWE-89, A03) ─────────────────────────────
// BAD: User input interpolated directly into SQL query
app.get("/user", (req, res) => {
  const username = req.query.username;
  // VULNERABLE: template literal in SQL — classic injection
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  db.query(query, (err, results) => {
    res.json(results);
  });
});


// ── VULNERABILITY 3: XSS via innerHTML (CWE-79, A03) ─────────────────────────
// BAD: User data assigned to innerHTML without sanitization
app.get("/greet", (req, res) => {
  const name = req.query.name || "World";
  // VULNERABLE: attacker can inject <script>alert(1)</script>
  const html = `
    <html><body>
      <div id="greeting"></div>
      <script>
        document.getElementById('greeting').innerHTML = 'Hello, ${name}!';
      </script>
    </body></html>`;
  res.send(html);
});


// ── VULNERABILITY 4: Command Injection (CWE-78, A03) ─────────────────────────
// BAD: exec() with user-controlled template literal
app.get("/ping", (req, res) => {
  const host = req.query.host;
  // VULNERABLE: attacker can append ; rm -rf / or similar
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.send(stdout);
  });
});


// ── VULNERABILITY 5: Path Traversal (CWE-22, A01) ────────────────────────────
// BAD: path.join with user-controlled req.params
app.get("/file/:name", (req, res) => {
  // VULNERABLE: ../../etc/passwd traversal possible
  const filePath = path.join("/var/data", req.params.name);
  res.sendFile(filePath);
});


// ── VULNERABILITY 6: eval() Usage (CWE-95, A05) ──────────────────────────────
// BAD: eval() on user input enables arbitrary code execution
app.post("/calculate", (req, res) => {
  const expression = req.body.expression;
  // VULNERABLE: allows code injection (e.g., process.exit() or file reads)
  const result = eval(expression);
  res.json({ result });
});


// ── VULNERABILITY 7: JWT Without Algorithm Specification (CWE-347, A07) ──────
// BAD: jwt.verify without specifying allowed algorithms
app.get("/profile", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  // VULNERABLE: attacker can use alg=none to bypass verification
  const payload = jwt.verify(token, JWT_SECRET);
  res.json(payload);
});


// ── VULNERABILITY 8: Weak Crypto for Password (CWE-327, A02) ─────────────────
// BAD: MD5 used to hash passwords
function hashPasswordBad(password) {
  // VULNERABLE: MD5 is reversible via rainbow tables
  return crypto.createHash("md5").update(password).digest("hex");
}

function hashPasswordAlsoBad(password) {
  // VULNERABLE: SHA1 is also insufficient for passwords
  return crypto.createHash("sha1").update(password).digest("hex");
}


// ── VULNERABILITY 9: Prototype Pollution (CWE-1321, A08) ─────────────────────
// BAD: user-controlled key used as object property
app.post("/config", (req, res) => {
  const settings = {};
  // VULNERABLE: req.body.key could be '__proto__' to pollute prototype
  settings[req.body.key] = req.body.value;
  res.json({ saved: true });
});


// ── VULNERABILITY 10: Sensitive Data in Logs (CWE-532, A09) ──────────────────
// BAD: passwords and tokens logged to console
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  // VULNERABLE: password written to logs
  console.log(`Login attempt: username=${username} password=${password}`);

  if (username === "admin" && password === DB_PASSWORD) {
    const token = jwt.sign({ user: username }, JWT_SECRET);
    // VULNERABLE: token logged
    console.log(`Issued token: ${token}`);
    res.json({ token });
  } else {
    res.status(401).json({ error: "Unauthorized" });
  }
});


// ── VULNERABILITY 11: XSS via res.send with req.query (CWE-79, A03) ──────────
// BAD: unsanitized query parameter echoed in response
app.get("/search", (req, res) => {
  // VULNERABLE: reflected XSS
  res.send(`<h1>Search results for: ${req.query.q}</h1>`);
});


app.listen(3000, () => console.log("Server running on port 3000"));
