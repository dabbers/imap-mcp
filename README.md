# imap-mcp-ro

Read-only IMAP MCP server (Streamable HTTP, stateless) for Claude custom connectors.

## Tools
- `list_folders` — allowed folders only
- `search_messages` — envelope metadata, newest first, filtered by from/to/subject/date, clamped to `MAX_DAYS_BACK`. **No body text search** (it would be a code-guessing oracle).
- `get_message` — plain-text body (HTML flattened, links/images stripped, length-capped), attachment list only

## Read-only guarantees
- Mailboxes opened with `EXAMINE` (`readOnly: true`); fetches use `BODY.PEEK`, so nothing is marked read.
- No write, move, delete, flag, append or SMTP code paths exist.
- Folder allowlist and date window enforced server-side.
- The IMAP credential itself should still be an IMAP-only identity on a copy mailbox (below) — the app is read-only by construction, not at the protocol level.

## Auth-mail filtering (`src/sensitivity.ts`)
Each message is scored locally on sender, subject, body, recipients and attachment filenames: OTP/2FA wording, a code near a keyword (digits, dashed, or 5–8-char alphanumerics like Steam's), standalone code lines, "code is …" phrasing, backup/recovery codes, temporary passwords, tokenized or auth-path links, short expiry, "don't share", password-reset language, blocklisted senders. Before scoring, text is NFKC-normalized, every script's decimal digits are mapped to ASCII, invisible/bidi characters are stripped, and spaced digits collapsed. Subject, from/to/cc and filenames in *every* response go through the same code/link masking as bodies.

- Score ≥ `SENSITIVE_THRESHOLD`: **omitted from search results entirely** and `get_message` returns metadata with `subject: "[withheld]"` and no body. Withheld mail is never downloaded.
- Below threshold: codes and auth links are still masked inline.
- All regexes are linear; bodies are capped at `MAX_BODY_CHARS` before scoring. `test/sens.mjs` includes a 1 MB ReDoS regression.

Run `npm run build && node test/sens.mjs` to check the rules.

## Access control (three layers)
1. **IP allowlist** — the MCP endpoint and the machine-called OAuth endpoints (`/oauth/token`, `/oauth/register`) accept only Anthropic's published outbound range `160.79.104.0/21` (`ALLOWED_CIDRS`). Enforced in the app via `X-Forwarded-For` from Traefik, and again at the edge by the Traefik `ipallowlist` labels in compose. Anything else gets 403 and a `blocked_ip` log line. The TOTP page is deliberately *not* IP-restricted (you open it from your own browser). Check the range occasionally against Anthropic's IP page; if they add a range the connector will fail closed with 403s.
2. **OAuth with TOTP** — a built-in OAuth 2.1 server (DCR + PKCE S256, as claude.ai requires). The consent page asks for a 6-digit code from your authenticator app. Tokens are HMAC-signed, expire after `ACCESS_TOKEN_DAYS` (default 14) and **there are no refresh tokens**, so when one expires Claude shows the connector as disconnected and you reconnect by entering a fresh TOTP. TOTP guessing: 5 failures/min per IP then exponential lockout for that IP (so a flood can't lock *you* out), 300/min global ceiling, each accepted code is dead for the rest of its window (no replay). Auth codes are single-use and live 5 min; only `https://claude.ai/api/mcp/auth_callback` (and Claude Code's loopback) may be a redirect, and the code is PKCE-bound, so an attacker-initiated authorize link can't harvest a token even if you type a TOTP into it. The TOTP page sends `frame-ancestors 'none'`. `TOKEN_EPOCH`: change it to kill every token at once. Startup refuses a non-hex signing key or non-base32 TOTP secret (a silent decode to an empty key would make tokens forgeable).
3. **Secret URL path** — still required on top; treat the URL as a password.

Set up: `node dist/gen-totp.js` prints `TOTP_SECRET`, `TOKEN_SIGNING_KEY` and an `otpauth://` URI to add to 1Password/Authy/Google Authenticator. Connecting in claude.ai: add the connector URL with no client ID/secret (Claude self-registers), approve, enter the code.

`node test/oauth-flow.mjs` exercises the whole flow (401 → discovery → DCR → TOTP → PKCE → token → expiry).

## Exfiltration budgets
Sized for how an assistant uses mail, so a stolen token can't bulk-export. All sliding windows, global:

| Budget | Default |
|---|---|
| tool calls / minute | 10 |
| searches / hour | 40 |
| rows per search | ≤ 20 |
| message bodies / hour | 20 |
| message bodies / day | 80 |
| distinct messages / day | 60 (re-reads of the same uid don't count) |

Worst case with a valid token: **60 unique bodies in 24 h, then nothing until the window slides.** Withheld (sensitive) messages are never downloaded, so they cost nothing.

Over-budget calls return a tool error that tells the model not to retry. **Tripwire:** `TRIPWIRE_REJECTS` (5) rejected calls within an hour revokes the current token on the spot (logged as `TRIPWIRE`); the connector shows as disconnected and you must enter a fresh TOTP. A fresh TOTP clears the trip and the *hourly* windows so your new session isn't punished for the abuser's usage; the daily and distinct-uid caps are not reset, so re-authorizing never raises the exfiltration ceiling. The revocation epoch is persisted to `/tmp` (tmpfs), so a crash-restart does not un-revoke a token; a redeploy does.

A body-withheld read (sensitive verdict only after download) still counts against the body budgets — conservative on purpose.

Counters live in process memory and reset on container restart, which a token holder cannot trigger.

## Abuse limits
- `RATE_LIMIT_PER_MIN` (default 30) raw requests on the MCP endpoint; `MAX_CONCURRENT` (1) IMAP session, 8 queued.
- `MAX_MESSAGE_BYTES` (3 MB): larger mail is refused, not downloaded. IMAP connect/greeting timeouts 10 s.
- `mem_limit` 256 MB, `pids_limit` 64, log rotation, read-only root FS, no capabilities, non-root.
- With `PUBLIC_HOST` set, requests with any other `Host` header are rejected (403).

## Logging
One JSON line per tool call: timestamp, client IP (`X-Forwarded-For` via Traefik), user-agent, tool, folder, uid, result count, duration, and for withheld reads the score and matched signals. **Search terms and message content are never logged.**

## Deploy on Dokploy
1. Push this folder to a git repo; in Dokploy create a **Compose** app from it.
2. Set env vars from `.env.example` in the Environment tab.
3. Domains tab: add `mail-mcp.yourdomain` → service `imap-mcp`, port 3000, HTTPS. Set `PUBLIC_HOST` to the same name.
4. In claude.ai: Settings → Connectors → Add custom connector → `https://mail-mcp.yourdomain/mcp/<MCP_PATH_SECRET>`.
5. Check whether Traefik access logging is on (`/etc/dokploy/traefik/traefik.yml`, `accessLog:`). If it is, the secret path is written to disk on every request; disable it or add a redacting filter.

## Credential setup (Migadu)
Create an identity with a **custom password** and only "May access over IMAP" enabled (no send, POP3, ManageSieve, receive). Prefer pointing it at a dedicated copy mailbox fed by a forward rule, with retention matching `MAX_DAYS_BACK`, so the server never holds a credential to your primary mailbox. Set an expiry on the identity and rotate `MCP_PATH_SECRET` (re-add the connector) on any suspicion of leakage.

## Known limits
- If Anthropic changes its egress range, the allowlist fails closed — update `ALLOWED_CIDRS` and the Traefik label.
- If your domain is proxied through Cloudflare (orange cloud), the client IP Traefik sees is Cloudflare's and the allowlist will block everything. Keep it DNS-only, or configure Traefik to trust Cloudflare's `CF-Connecting-IP`.
- Heuristic filtering can miss unusually-worded OTP mail; the copy-mailbox + Sieve approach (don't copy known auth senders) is the stronger layer.
- Prompt injection via mail content is inherent to the use case: every result is labeled untrusted, but the model holding other write-capable connectors is the real risk surface.
