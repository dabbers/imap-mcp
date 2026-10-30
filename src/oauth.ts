// Minimal OAuth 2.1 authorization server for exactly one client (Claude) and one user (you).
// - Dynamic Client Registration (stateless: client_id is a signed blob of its redirect_uris)
// - Authorization code + PKCE S256; the "login" is a TOTP code from your authenticator
// - Access tokens are HMAC-signed, expire after ACCESS_TOKEN_DAYS, and there are NO refresh
//   tokens, so Claude must send you back to the TOTP page when a token expires.
// - TOKEN_EPOCH env: bump it to invalidate every token ever issued.

import crypto from "node:crypto";
import express, { type Request, type Response, type Router } from "express";
import { verifyTotp } from "./totp.js";

export interface OAuthConfig {
  issuer: string;            // https://mail-mcp.example.com
  resource: string;          // exact MCP URL incl. secret path
  signingKey: Buffer;
  totpSecret: string;
  accessTokenDays: number;
  readonly epoch: string;
  onAuthorized?: () => void;
  allowedRedirects: RegExp[];
}

// ---------- signed blobs ----------
function b64u(b: Buffer) { return b.toString("base64url"); }
function sign(key: Buffer, payload: object, kind: string): string {
  const body = b64u(Buffer.from(JSON.stringify({ ...payload, k: kind })));
  const mac = b64u(crypto.createHmac("sha256", key).update(body).digest());
  return `${body}.${mac}`;
}
function verify<T extends object>(key: Buffer, blob: string, kind: string): T | null {
  const parts = blob.split(".");
  if (parts.length !== 2) return null;
  const [body, mac] = parts;
  if (!/^[A-Za-z0-9_-]+$/.test(body) || !/^[A-Za-z0-9_-]{43}$/.test(mac)) return null;
  const want = crypto.createHmac("sha256", key).update(body).digest();
  const got = Buffer.from(mac, "base64url");
  if (want.length !== got.length || !crypto.timingSafeEqual(want, got)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p.k === kind ? (p as T) : null;
  } catch { return null; }
}

type Client = { rid: string[]; k: string };
type Code = { c: string; r: string; ch: string; exp: number; n: string; k: string };
type Token = { exp: number; e: string; n: string; k: string };

export function verifyAccessToken(cfg: OAuthConfig, header: string | undefined): boolean {
  const t = header?.startsWith("Bearer ") ? header.slice(7) : "";
  if (!t) return false;
  const p = verify<Token>(cfg.signingKey, t, "at");
  return !!p && p.e === cfg.epoch && p.exp > Date.now() / 1000;
}

export function challenge(cfg: OAuthConfig, res: Response) {
  res.status(401)
    .set("WWW-Authenticate", `Bearer resource_metadata="${cfg.issuer}/.well-known/oauth-protected-resource${new URL(cfg.resource).pathname}"`)
    .json({ error: "unauthorized" });
}

// ---------- TOTP guess limiting ----------
// Per-IP: 5 failures/min, then exponential backoff for that IP only, so a flood from one
// address cannot lock the real user out. A small global ceiling still bounds total guess rate
// across many IPs (a 6-digit space needs ~500k guesses; 300/min global = ~28h expected, and
// the ±1-step window means a code is only valid ~90s, so distributed brute force is infeasible).
type IpState = { fails: number[]; lockedUntil: number };
const ipState = new Map<string, IpState>();
const globalFails: number[] = [];
function totpAttemptAllowed(ip: string): boolean {
  const now = Date.now();
  while (globalFails.length && globalFails[0] <= now - 60_000) globalFails.shift();
  if (globalFails.length >= 300) return false;
  const st = ipState.get(ip) ?? { fails: [], lockedUntil: 0 };
  if (st.lockedUntil > now) return false;
  st.fails = st.fails.filter((t) => t > now - 60_000);
  if (ipState.size > 10_000) ipState.clear(); // bound memory under a flood of spoofed/rotating IPs
  ipState.set(ip, st);
  return st.fails.length < 5;
}
function totpFailed(ip: string) {
  const now = Date.now();
  globalFails.push(now);
  const st = ipState.get(ip) ?? { fails: [], lockedUntil: 0 };
  st.fails.push(now);
  if (st.fails.length >= 5) st.lockedUntil = now + Math.min(3_600_000, 60_000 * 2 ** (st.fails.length - 5));
  ipState.set(ip, st);
}
// Replay cache: a code accepted once is dead for the rest of its window.
const usedTotp = new Map<string, number>();
const usedCodes = new Set<string>(); // single-use enforcement for auth codes (5-min lifetime)

const page = (title: string, body: string) => `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>${title}</title><style>body{font:16px system-ui;max-width:28rem;margin:4rem auto;padding:0 1rem;color:#222}input{font:inherit;font-size:1.5rem;letter-spacing:.3em;width:100%;padding:.5rem;box-sizing:border-box}button{font:inherit;padding:.6rem 1.2rem;margin-top:1rem}code{background:#eee;padding:.1em .3em}.err{color:#b00}</style>
<body>${body}</body>`;

export function oauthRouter(cfg: OAuthConfig): Router {
  const r = express.Router();
  const form = express.urlencoded({ extended: false, limit: "8kb" });
  const json = express.json({ limit: "8kb" });

  // --- discovery ---
  r.get("/.well-known/oauth-authorization-server", (_q, res) => res.json({
    issuer: cfg.issuer,
    authorization_endpoint: `${cfg.issuer}/oauth/authorize`,
    token_endpoint: `${cfg.issuer}/oauth/token`,
    registration_endpoint: `${cfg.issuer}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["mail:read"],
  }));
  const prm = (_q: Request, res: Response) => res.json({
    resource: cfg.resource,
    authorization_servers: [cfg.issuer],
    scopes_supported: ["mail:read"],
    bearer_methods_supported: ["header"],
  });
  // Only the secret-suffixed path serves the real resource URL. The bare path exists for
  // clients that probe it, but must not reveal the secret.
  r.get(`/.well-known/oauth-protected-resource${new URL(cfg.resource).pathname}`, prm);
  r.get("/.well-known/oauth-protected-resource", (_q, res) => res.status(404).end());

  // --- dynamic client registration (stateless) ---
  r.post("/oauth/register", json, (q, res) => {
    const uris: unknown = q.body?.redirect_uris;
    if (!Array.isArray(uris) || uris.length === 0 || !uris.every((u) => typeof u === "string" && cfg.allowedRedirects.some((re) => re.test(u)))) {
      return res.status(400).json({ error: "invalid_redirect_uri", error_description: "redirect_uri not allowed" });
    }
    const client_id = sign(cfg.signingKey, { rid: uris }, "cl");
    res.status(201).json({
      client_id, redirect_uris: uris, token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"], response_types: ["code"], client_name: String(q.body?.client_name ?? "client").slice(0, 100),
    });
  });

  // --- authorize: show TOTP form ---
  function parseAuthz(src: Record<string, unknown>) {
    const client_id = String(src.client_id ?? "");
    const redirect_uri = String(src.redirect_uri ?? "");
    const code_challenge = String(src.code_challenge ?? "");
    const state = String(src.state ?? "");
    const cl = verify<Client>(cfg.signingKey, client_id, "cl");
    if (!cl) return { err: "unknown client_id" };
    if (!cl.rid.includes(redirect_uri)) return { err: "redirect_uri not registered" };
    if (String(src.response_type ?? "code") !== "code") return { err: "unsupported response_type" };
    if (String(src.code_challenge_method ?? "") !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(code_challenge)) return { err: "PKCE S256 required" };
    return { client_id, redirect_uri, code_challenge, state };
  }

  r.use("/oauth/authorize", (_q, res, next) => {
    res.set({ "X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'; default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
      "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });
    next();
  });
  r.get("/oauth/authorize", (q, res) => {
    const a = parseAuthz(q.query as Record<string, unknown>);
    if ("err" in a) return res.status(400).send(page("Error", `<h1>Invalid request</h1><p class=err>${a.err}</p>`));
    const host = new URL(a.redirect_uri).host;
    const hidden = ["client_id", "redirect_uri", "code_challenge", "state"]
      .map((k) => `<input type=hidden name=${k} value="${(a as any)[k].replace(/"/g, "&quot;")}">`).join("");
    res.send(page("Connect mail", `<h1>Connect read-only mail</h1>
<p>Granting <code>${host}</code> read access for <b>${cfg.accessTokenDays} days</b>. Enter the current code from your authenticator.</p>
<form method=post action="/oauth/authorize">${hidden}<input type=hidden name=code_challenge_method value=S256>
<input name=totp inputmode=numeric autocomplete=one-time-code pattern="[0-9]{6}" placeholder="000000" autofocus required>
<button>Approve</button></form>`));
  });

  r.post("/oauth/authorize", form, (q, res) => {
    const a = parseAuthz(q.body ?? {});
    if ("err" in a) return res.status(400).send(page("Error", `<h1>Invalid request</h1><p class=err>${a.err}</p>`));
    const ip = q.ip ?? "";
    if (!totpAttemptAllowed(ip)) return res.status(429).send(page("Slow down", "<h1>Too many attempts</h1><p>Try again later.</p>"));
    const totp = String(q.body?.totp ?? "");
    const now = Date.now();
    for (const [k, t] of usedTotp) if (t <= now - 120_000) usedTotp.delete(k);
    if (!/^\d{6}$/.test(totp) || usedTotp.has(totp) || !verifyTotp(cfg.totpSecret, totp)) {
      totpFailed(ip);
      console.log(JSON.stringify({ ts: new Date().toISOString(), oauth: "totp_fail", ip }));
      return res.status(401).send(page("Wrong code", `<h1>Wrong code</h1><p class=err>Go back and try again.</p>`));
    }
    usedTotp.set(totp, now);
    const nonce = crypto.randomBytes(12).toString("base64url");
    const code = sign(cfg.signingKey, { c: a.client_id, r: a.redirect_uri, ch: a.code_challenge, exp: Math.floor(Date.now() / 1000) + 300, n: nonce }, "ac");
    console.log(JSON.stringify({ ts: new Date().toISOString(), oauth: "totp_ok", ip: q.ip }));
    const u = new URL(a.redirect_uri);
    u.searchParams.set("code", code);
    if (a.state) u.searchParams.set("state", a.state);
    res.redirect(302, u.toString());
  });

  // --- token ---
  r.post("/oauth/token", form, (q, res) => {
    const b = q.body ?? {};
    if (b.grant_type === "refresh_token") return res.status(400).json({ error: "invalid_grant", error_description: "refresh not supported; re-authorize" });
    if (b.grant_type !== "authorization_code") return res.status(400).json({ error: "unsupported_grant_type" });
    const c = verify<Code>(cfg.signingKey, String(b.code ?? ""), "ac");
    if (!c || c.exp < Date.now() / 1000 || usedCodes.has(c.n)) return res.status(400).json({ error: "invalid_grant" });
    if (String(b.client_id ?? "") !== c.c || String(b.redirect_uri ?? c.r) !== c.r) return res.status(400).json({ error: "invalid_grant" });
    const ver = String(b.code_verifier ?? "");
    const want = crypto.createHash("sha256").update(ver).digest("base64url");
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(ver) || want !== c.ch) return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
    usedCodes.add(c.n);
    const t = setTimeout(() => usedCodes.delete(c.n), 600_000); (t as any).unref?.();

    const expires_in = Math.floor(cfg.accessTokenDays * 86400);
    const access_token = sign(cfg.signingKey, { exp: Math.floor(Date.now() / 1000) + expires_in, e: cfg.epoch, n: crypto.randomBytes(8).toString("base64url") }, "at");
    console.log(JSON.stringify({ ts: new Date().toISOString(), oauth: "token_issued", ip: q.ip, expires_in }));
    cfg.onAuthorized?.();
    res.set("Cache-Control", "no-store").json({ access_token, token_type: "Bearer", expires_in, scope: "mail:read" });
  });

  return r;
}
