import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { verifyTotp, base32Encode } from "../dist/totp.js";

const SECRET = crypto.randomBytes(32).toString("hex");
const TOTP = base32Encode(crypto.randomBytes(20));
const PORT = 3998, HOST = `localhost:${PORT}`;
const env = { ...process.env, IMAP_USER: "x", IMAP_PASS: "x", MCP_PATH_SECRET: SECRET, PORT: String(PORT),
  PUBLIC_HOST: HOST, TOTP_SECRET: TOTP, TOKEN_SIGNING_KEY: crypto.randomBytes(32).toString("hex"),
  ACCESS_TOKEN_DAYS: "0.0001", // ~8.6s, to test expiry
  ALLOWED_CIDRS: process.argv[2] ?? "" };           // "" = allowlist off for the happy path
const srv = spawn("node", ["dist/index.js"], { env, stdio: ["ignore", "pipe", "pipe"] });
srv.stdout.on("data", (d) => process.stdout.write("  [srv] " + d));
srv.stderr.on("data", (d) => process.stdout.write("  [srv!] " + d));
await new Promise((r) => setTimeout(r, 1200));

// Issuer is https:// in metadata but we're testing over http: rewrite.
const B = `http://${HOST}`, fix = (u) => u.replace(`https://${HOST}`, B);
const mcp = `${B}/mcp/${SECRET}`;
const H = { "content-type": "application/json", accept: "application/json, text/event-stream" };
let fails = 0; const check = (name, ok, extra = "") => { console.log(`${ok ? "PASS" : "FAIL"}  ${name} ${extra}`); if (!ok) fails++; };

// 1. unauthenticated -> 401 with resource_metadata pointer
let r = await fetch(mcp, { method: "POST", headers: H, body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' });
const www = r.headers.get("www-authenticate") ?? "";
check("401 + WWW-Authenticate", r.status === 401 && www.includes("resource_metadata="), www);

// 2. discovery
const prmUrl = fix(/resource_metadata="([^"]+)"/.exec(www)[1]);
const prm = await (await fetch(prmUrl)).json();
check("PRM resource matches MCP URL", fix(prm.resource) === mcp);
const as = await (await fetch(fix(prm.authorization_servers[0]) + "/.well-known/oauth-authorization-server")).json();
check("AS metadata advertises S256 + DCR", as.code_challenge_methods_supported?.[0] === "S256" && !!as.registration_endpoint);

// 3. DCR
r = await fetch(fix(as.registration_endpoint), { method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ client_name: "Claude", redirect_uris: ["https://claude.ai/api/mcp/auth_callback"] }) });
const client = await r.json();
check("DCR registers claude.ai redirect", r.status === 201 && !!client.client_id);
r = await fetch(fix(as.registration_endpoint), { method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ redirect_uris: ["https://evil.example/cb"] }) });
check("DCR rejects foreign redirect", r.status === 400);

// 4. authorize with PKCE + TOTP
const verifier = crypto.randomBytes(48).toString("base64url");
const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: "https://claude.ai/api/mcp/auth_callback",
  code_challenge: challenge, code_challenge_method: "S256", state: "xyz" });
r = await fetch(`${fix(as.authorization_endpoint)}?${q}`);
check("authorize page renders TOTP form", r.status === 200 && (await r.text()).includes('name=totp'));
// compute a valid TOTP the same way an authenticator would
const { createHmac } = crypto;
function totpNow(b32) { for (let c = 0; c < 1e6; c++) { const s = String(c).padStart(6, "0"); if (verifyTotp(b32, s)) return s; } }
const good = totpNow(TOTP);
const bad = String((Number(good) + 1) % 1e6).padStart(6, "0");
const post = (totp) => fetch(fix(as.authorization_endpoint), { method: "POST", redirect: "manual",
  headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ ...Object.fromEntries(q), totp }) });
r = await post(bad); check("wrong TOTP rejected", r.status === 401);
r = await post(good);
const loc = r.headers.get("location") ?? "";
check("right TOTP -> 302 to claude.ai with code+state", r.status === 302 && loc.startsWith("https://claude.ai/api/mcp/auth_callback?code=") && loc.includes("state=xyz"));
const code = new URL(loc).searchParams.get("code");

// 5. token exchange
const tok = (body) => fetch(fix(as.token_endpoint), { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(body) });
r = await tok({ grant_type: "authorization_code", code, client_id: client.client_id, redirect_uri: "https://claude.ai/api/mcp/auth_callback", code_verifier: "wrong-verifier-wrong-verifier-wrong-verifier-wrong" });
check("wrong PKCE verifier rejected", r.status === 400);
r = await tok({ grant_type: "authorization_code", code, client_id: client.client_id, redirect_uri: "https://claude.ai/api/mcp/auth_callback", code_verifier: verifier });
const t = await r.json();
check("token issued, no refresh_token", r.status === 200 && !!t.access_token && !t.refresh_token, `expires_in=${t.expires_in}`);
r = await tok({ grant_type: "authorization_code", code, client_id: client.client_id, redirect_uri: "https://claude.ai/api/mcp/auth_callback", code_verifier: verifier });
check("code is single-use", r.status === 400);
r = await tok({ grant_type: "refresh_token", refresh_token: "anything" });
check("refresh -> invalid_grant", r.status === 400 && (await r.json()).error === "invalid_grant");

// 6. authenticated MCP call
r = await fetch(mcp, { method: "POST", headers: { ...H, authorization: `Bearer ${t.access_token}` }, body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' });
check("bearer token accepted on MCP", r.status === 200 && (await r.text()).includes("get_message"));
r = await fetch(mcp, { method: "POST", headers: { ...H, authorization: `Bearer ${t.access_token.slice(0, -2)}xx` }, body: '{}' });
check("tampered token rejected", r.status === 401);

// 7. expiry
await new Promise((r) => setTimeout(r, 9500));
r = await fetch(mcp, { method: "POST", headers: { ...H, authorization: `Bearer ${t.access_token}` }, body: '{}' });
check("expired token -> 401 (Claude will re-prompt for TOTP)", r.status === 401);

srv.kill(); process.exit(fails ? 1 : 0);
