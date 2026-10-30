// One-off: prints a fresh TOTP secret to put in TOTP_SECRET, plus the otpauth URI
// to add to your authenticator app. Run: node dist/gen-totp.js [label]
import crypto from "node:crypto";
import { base32Encode, otpauthUri } from "./totp.js";

const secret = base32Encode(crypto.randomBytes(20));
const label = process.argv[2] ?? "mail-mcp";
console.log(`TOTP_SECRET=${secret}`);
console.log(`\nAdd to your authenticator (manual entry, time-based, 6 digits):\n${otpauthUri(secret, label, "imap-mcp-ro")}`);
console.log(`\nAlso generate:\nTOKEN_SIGNING_KEY=${crypto.randomBytes(32).toString("hex")}`);
