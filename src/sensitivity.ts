// Heuristic detection of auth-sensitive mail: OTP codes, magic links, password resets, 2FA.
// Deterministic and local: nothing is sent to another service to classify.
//
// All regexes here are linear-time on their input and are only ever run on
// normalize()d, length-capped text. URLs are tokenized first and each URL is
// capped at MAX_URL_LEN before any pattern is applied to it (avoids backtracking blowups).

export interface Verdict {
  score: number;
  sensitive: boolean;
  reasons: string[];
}

export interface SensitivityConfig {
  threshold: number;
  senders: string[]; // substrings matched against the From address (e.g. "accounts.google.com")
}

const MAX_URL_LEN = 2048;

// Unicode decimal digits come in contiguous runs of 10 starting at a zero; find the zero.
function digitValue(ch: string): number {
  const cp = ch.codePointAt(0)!;
  if (cp >= 0x30 && cp <= 0x39) return cp - 0x30;
  for (let z = cp; z > cp - 10; z--) if (/\p{Nd}/u.test(String.fromCodePoint(z)) && !/\p{Nd}/u.test(String.fromCodePoint(z - 1))) return cp - z;
  return cp % 10; // unreachable for well-formed Nd blocks
}

/** Canonicalize text so spacing/unicode tricks can't dodge the digit patterns. */
// Invisible/format characters an attacker could use to split a code. Built from code points
// so the source stays plain ASCII: soft hyphen, CGJ, zero-width + bidi marks, bidi embeddings,
// invisible operators, bidi isolates, Hangul filler, BOM, halfwidth filler.
const INVISIBLE_RANGES: [number, number][] = [
  [0xad, 0xad], [0x34f, 0x34f], [0x200b, 0x200f], [0x202a, 0x202e], [0x2060, 0x2064],
  [0x2066, 0x2069], [0x3164, 0x3164], [0xfeff, 0xfeff], [0xffa0, 0xffa0],
];
const INVISIBLE = new RegExp(
  "[" + INVISIBLE_RANGES.map(([a, b]) => String.fromCodePoint(a) + (b > a ? "-" + String.fromCodePoint(b) : "")).join("") + "]",
  "gu",
);

export function normalize(text: string): string {
  let t = text.normalize("NFKC");                 // fullwidth digits -> ASCII
  // zero-width, soft hyphen, invisible operators, bidi controls, Hangul filler, CGJ
  t = t.replace(INVISIBLE, "");
  // any script's decimal digit -> ASCII (Arabic-Indic, Devanagari, Bengali, ...)
  t = t.replace(/\p{Nd}/gu, (d) => String(digitValue(d)));
  t = t.replace(/\r\n?/g, "\n");
  // "4 8 2 9 1 3" or "4\n8\n2\n9" -> "482913" (html-to-text renders per-cell digits like this)
  t = t.replace(/\b\d(?:[ \t\n]\d){3,7}\b/g, (m) => m.replace(/[ \t\n]/g, ""));
  return t;
}

const SUBJECT_RULES: [RegExp, number, string][] = [
  [/\b(verification|security|login|sign[- ]?in|access|authentication|confirmation)\s+code\b/i, 5, "subject: code"],
  [/\b(one[- ]time|otp|passcode|2fa|two[- ]factor|mfa|multi[- ]factor)\b/i, 5, "subject: OTP/2FA"],
  [/\b(magic|sign[- ]?in|login)\s+link\b/i, 5, "subject: login link"],
  [/\b(reset|change|recover)\s+(your\s+)?password\b|\bpassword\s+reset\b/i, 5, "subject: password reset"],
  [/\b(verify|confirm)\s+(your\s+)?(email|account|identity|device|login)\b/i, 3, "subject: verify"],
  [/^\s*(sign|log)[- ]?in\s+to\b/i, 3, "subject: sign in to"],
  [/\bnew\s+(sign[- ]?in|login|device)\b|\bsecurity\s+alert\b/i, 2, "subject: security alert"],
  [/\b(backup|recovery)\s+codes?\b/i, 5, "subject: backup/recovery codes"],
  [/\b(temporary|temp|new)\s+password\b|\bguard\s+code\b|\baccess\s+code\b/i, 5, "subject: temporary password / guard code"],
  [/\b\d{4,8}\b.{0,20}\b(is your|code)\b|\bcode\b.{0,20}\b\d{4,8}\b/i, 5, "subject: contains code"],
];

// Code-shaped tokens: 123456, 123-456, 123 456, G-7HQ2KD, ABCD-1234
const CODE = String.raw`(\d{3}[ -]?\d{3,4}|\d{4,10}|[A-Za-z0-9]{1,4}-[A-Za-z0-9]{3,6}|(?=[A-Za-z]*\d)[A-Za-z0-9]{5,8})`;
const KW = String.raw`(?:code|codes|otp|passcode|pin|verification|one[- ]time|security code|token|temporary password|temp password)`;

// A code within a short span of a code keyword, either order.
const CODE_NEAR_KEYWORD = [
  new RegExp(String.raw`\b${KW}\b(?:[^\n]{0,50}?|[^\n]{0,30}\n[^\n]{0,30}?)\b${CODE}\b`, "gi"),
  new RegExp(String.raw`\b${CODE}\b[^\n]{0,30}?\b(?:is your|is the|verification|code)\b`, "gi"),
  // "Use 482913 to sign in / to log in / to continue / to verify"
  new RegExp(String.raw`\b${CODE}\b[^\n]{0,20}?\bto\s+(?:sign[- ]?in|log[- ]?in|continue|verify|confirm|proceed)\b`, "gi"),
];
// A line containing only a code (how most OTP mails render the big number).
// Tight "code is 123456" / "code: 123456" phrasing: near-certain OTP.
const CODE_IS = new RegExp(String.raw`\b(?:code|otp|passcode|pin|password)\s*(?:is|:)\s*${CODE}\b`, "i");
const CODE_ALONE = /^[ \t]*(\d{3}[ -]?\d{3,4}|\d{4,10}|[A-Za-z0-9]{1,4}-[A-Za-z0-9]{3,6}|(?=[A-Za-z]*\d)[A-Za-z0-9]{5,8})[ \t]*$/gm;

// Linear URL tokenizer; each URL is then tested with bounded patterns.
const URL_TOKEN = /https?:\/\/[^\s<>"']+/gi;
const AUTH_QUERY = /[?&](?:token|code|key|sig|signature|otp|auth|ticket|nonce|t|k|oobcode|access_token|magic|login_token|verification)=[^&\s]{6,}/i;
const AUTH_PATH = /\/(?:magic|verify|verification|reset|confirm|login|signin|sign-in|auth|activate|sso|password|otp|token)(?:\/|[?#]|$)/i;
const LONG_PATH_TOKEN = /\/[A-Za-z0-9_\-.]{20,}(?:\/|[?#]|$)/;

/** 0 = not auth-ish, 3 = token-bearing, 5 = token on an auth path (e.g. /login?code=…). */
function authUrlScore(url: string): number {
  const u = url.slice(0, MAX_URL_LEN);
  const q = AUTH_QUERY.test(u), p = AUTH_PATH.test(u);
  if (q && p) return 5;
  if (q || (p && LONG_PATH_TOKEN.test(u))) return 3;
  return 0;
}
const isAuthUrl = (u: string) => authUrlScore(u) > 0;

function maxAuthUrlScore(text: string): number {
  URL_TOKEN.lastIndex = 0;
  let best = 0, m: RegExpExecArray | null;
  while ((m = URL_TOKEN.exec(text))) best = Math.max(best, authUrlScore(m[0]));
  return best;
}

const BODY_RULES: [RegExp, number, string][] = [
  [/\b(expires?|valid)\s+(in|for|within)\s+\d+\s*(min|minute|hour|hr|second)/i, 2, "body: short expiry"],
  [/\bif you did(n'?t| not)\s+(request|try|make|attempt|initiate)/i, 1, "body: didn't-request language"],
  [/\bdo not share|never share|don'?t share (this|it|the code)/i, 2, "body: do-not-share"],
  [/\b(reset|choose|set|create)\s+(a\s+new|your)\s+password\b/i, 3, "body: password reset"],
  [/\b(backup|recovery)\s+codes?\b/i, 5, "body: backup/recovery codes"],
  [/\b(temporary|temp)\s+password\b/i, 5, "body: temporary password"],
  [/\b(guard|access|login|sign[- ]?in)\s+code\b/i, 3, "body: guard/access code"],
  [/\b(sign|log)\s+in\s+(to|with)\b.{0,40}\b(link|button|click)/i, 2, "body: login link"],
];

const AUTH_LOCALPART = /^(no-?reply|security|accounts?|verify|verification|auth|login|identity|otp)\b/i;

export function scoreMessage(
  input: { subject: string; fromAddress: string; body?: string; aux?: string[] },
  cfg: SensitivityConfig,
): Verdict {
  const reasons: string[] = [];
  let score = 0;
  const add = (n: number, why: string) => { score += n; reasons.push(why); };

  const from = input.fromAddress.toLowerCase();
  if (cfg.senders.some((s) => s && from.includes(s.toLowerCase()))) add(100, "sender on blocklist");
  if (AUTH_LOCALPART.test(from)) add(1, "sender looks automated/auth");

  const subject = normalize(input.subject).slice(0, 1000);
  for (const [re, w, why] of SUBJECT_RULES) if (re.test(subject)) add(w, why);

  const extra = (input.aux ?? []).map(normalize).join("\n");
  if (extra && (CODE_NEAR_KEYWORD.some((re) => { re.lastIndex = 0; return re.test(extra); }) || CODE_IS.test(extra))) add(4, "header/filename: code near keyword");
  if (input.body !== undefined) {
    const b = normalize(input.body);
    if (CODE_NEAR_KEYWORD.some((re) => { re.lastIndex = 0; return re.test(b); })) add(4, "body: code near keyword");
    CODE_ALONE.lastIndex = 0;
    if (CODE_ALONE.test(b)) add(2, "body: standalone code line");
    if (CODE_IS.test(b)) add(2, "body: 'code is' phrasing");
    const url = maxAuthUrlScore(b);
    if (url) add(url, url >= 5 ? "body: token on auth path" : "body: tokenized link");
    for (const [re, w, why] of BODY_RULES) if (re.test(b)) add(w, why);
    // Expiry language plus any code-shaped token is enough on its own.
    if (reasons.includes("body: short expiry") && /\b\d{4,8}\b/.test(b) && score < cfg.threshold) {
      add(cfg.threshold - score, "body: expiry + code-shaped number");
    }
  }

  return { score, sensitive: score >= cfg.threshold, reasons };
}

/** Defense in depth for mail below the threshold: mask codes and auth links inline. */
export function redactInline(text: string): string {
  let t = normalize(text);
  t = t.replace(URL_TOKEN, (u) => (isAuthUrl(u) ? "[auth link removed]" : u));
  for (const re of CODE_NEAR_KEYWORD) {
    t = t.replace(re, (m, code: string) => m.replace(code, "[code redacted]"));
  }
  t = t.replace(CODE_ALONE, "[code redacted]");
  return t;
}
