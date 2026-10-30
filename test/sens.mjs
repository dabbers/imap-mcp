import { scoreMessage, redactInline, normalize } from "../dist/sensitivity.js";
const cfg = { threshold: 5, senders: ["accounts.google.com"] };
const cases = [
  ["OTP subject", { subject: "482913 is your Slack confirmation code", fromAddress: "no-reply@slack.com" }, true],
  ["OTP body only", { subject: "Your account", fromAddress: "hello@shop.com", body: "Your verification code is 739201. It expires in 10 minutes. Do not share it." }, true],
  ["Magic link", { subject: "Sign in to Linear", fromAddress: "notifications@linear.app", body: "Click to log in to Linear with this link: https://linear.app/auth/magic/AbCdEfGh1234567890XyZ" }, true],
  ["Password reset", { subject: "Reset your password", fromAddress: "support@x.com", body: "Choose a new password: https://x.com/reset?token=abcdef1234567890abcdef" }, true],
  ["Blocklisted sender", { subject: "Security alert", fromAddress: "no-reply@accounts.google.com", body: "New sign-in on Mac" }, true],
  ["Use N to sign in", { subject: "Acme", fromAddress: "hi@acme.com", body: "Use 482913 to sign in to Acme. It expires in 10 minutes." }, true],
  ["Spaced digits", { subject: "Your verification code", fromAddress: "hi@acme.com", body: "Your verification code\n\n4 8 2 9 1 3\n\nExpires in 10 minutes" }, true],
  ["One digit per line", { subject: "Acme", fromAddress: "hi@acme.com", body: "Your code:\n4\n8\n2\n9\n1\n3" }, true],
  ["Fullwidth digits", { subject: "Acme", fromAddress: "hi@acme.com", body: "Your code is ４８２９１３" }, true],
  ["Short query token", { subject: "Welcome", fromAddress: "hi@acme.com", body: "Finish signing in: https://app.example/login?code=abc123XYZ" }, true],
  ["Steam Guard", { subject: "Your Steam account: Access from new computer", fromAddress: "noreply@steampowered.com", body: "Here is the Steam Guard code you need to login to account dab:\n\nK7Q2M\n\nIf you did not request this..." }, true],
  ["Alnum no dash", { subject: "Acme", fromAddress: "hi@acme.com", body: "Your verification code: K7Q2M" }, true],
  ["Lowercase alnum", { subject: "Acme", fromAddress: "hi@acme.com", body: "Your confirmation code is a8f3k2jd" }, true],
  ["9-digit code", { subject: "Acme", fromAddress: "hi@acme.com", body: "Your verification code is 482913775" }, true],
  ["Backup codes", { subject: "Your backup codes", fromAddress: "hi@acme.com", body: "abcd-efgh\nijkl-mnop\nqrst-uvwx" }, true],
  ["Temporary password", { subject: "Welcome to Acme", fromAddress: "hi@acme.com", body: "Your temporary password is Xk9#pLm2!qR" }, true],
  ["Arabic-Indic digits", { subject: "Acme", fromAddress: "hi@acme.com", body: "Your code is ٤٨٢٩١٣" }, true],
  ["Devanagari digits", { subject: "Acme", fromAddress: "hi@acme.com", body: "Your code is ४८२९१३" }, true],
  ["Soft hyphens", { subject: "Acme", fromAddress: "hi@acme.com", body: "Your code is 4\u00AD8\u00AD2\u00AD9\u00AD1\u00AD3" }, true],
  ["Code in filename", { subject: "Doc", fromAddress: "hi@acme.com", body: "See attached.", aux: ["hi@acme.com", "you@x.com", "your-code-482913.pdf"] }, false], // scored but body-less: redaction handles the filename
  ["Order email", { subject: "Order #482913 shipped", fromAddress: "orders@amazon.com", body: "Your order 482913 has shipped. Track: https://amazon.com/track?id=123" }, false],
  ["Calendar invite", { subject: "Invitation: Standup @ Mon 9:30", fromAddress: "calendar@calendly.com", body: "Meeting room 2041, dial-in 555 0199" }, false],
  ["Newsletter", { subject: "This week in TCG prices", fromAddress: "news@tcgplayer.com", body: "Use promo code SAVE20 at checkout. Unsubscribe: https://tcg.com/u?e=x" }, false],
  ["Receipt w/ expiry", { subject: "Your Lyft receipt", fromAddress: "no-reply@lyftmail.com", body: "Total $23.10. Valid for 30 days for disputes." }, false],
  ["Phone number", { subject: "Call me", fromAddress: "mom@family.com", body: "New number is 425 555 0133, call after 6" }, false],
];
let fail = 0;
const check2 = (n, ok) => { console.log(`${ok ? "PASS" : "FAIL"}  ${n}`); if (!ok) fail++; };
for (const [name, input, want] of cases) {
  const v = scoreMessage(input, cfg);
  const ok = v.sensitive === want; if (!ok) fail++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name.padEnd(20)} score=${String(v.score).padStart(3)}  ${v.reasons.join("; ")}`);
}

// ReDoS regression: must stay linear.
for (const n of [10_000, 100_000, 1_000_000]) {
  const evil = "http://x" + "/verify/ab".repeat(n / 10) + "!";
  const t0 = performance.now();
  scoreMessage({ subject: "x", fromAddress: "x@x", body: evil }, cfg);
  redactInline(evil);
  const ms = performance.now() - t0;
  const ok = ms < 2000; if (!ok) fail++;
  console.log(`${ok ? "PASS" : "FAIL"}  redos ${String(n).padStart(8)} chars  ${ms.toFixed(0)} ms`);
}

const r1 = redactInline("Your Steam Guard code: K7Q2M\nBackup: abcd-efgh\nFile your-code-482913.pdf\nMeeting at 10am room 2041");
console.log("\nRedaction (Steam/backup/filename):", JSON.stringify(r1));
check2("Steam alnum code redacted", !r1.includes("K7Q2M"));
check2("room number untouched", r1.includes("room 2041"));
console.log("\nInline redaction:", redactInline("Hi, the code is 123 456 btw.\n\n  884210  \nSign-in code: G-7HQ2KD\nLink https://a.com/verify/abcdefghijklmnopqrst done"));
console.log("normalize:", JSON.stringify(normalize("4 8 2 9 1 3 / ４８２９１３ / 425 555 0133")));
process.exit(fail ? 1 : 0);
