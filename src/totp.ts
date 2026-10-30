import crypto from "node:crypto";

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Buffer): string {
  let bits = 0, value = 0, out = "";
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Buffer {
  if (!/^[A-Z2-7]+$/.test(s)) throw new Error("secret is not canonical base32");
  const clean = s;
  const out: number[] = [];
  let bits = 0, value = 0;
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch); bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

function hotp(secret: Buffer, counter: number, digits = 6): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac("sha1", secret).update(msg).digest();
  const off = h[h.length - 1] & 0xf;
  const code = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(code % 10 ** digits).padStart(digits, "0");
}

/** RFC 6238, 30s step, ±1 step tolerance. Constant-time compare. */
export function verifyTotp(secretB32: string, code: string, now = Date.now()): boolean {
  const secret = base32Decode(secretB32);
  const step = Math.floor(now / 30_000);
  const given = Buffer.from(code.replace(/\s/g, ""));
  let ok = false;
  for (const c of [step - 1, step, step + 1]) {
    const want = Buffer.from(hotp(secret, c));
    if (want.length === given.length && crypto.timingSafeEqual(want, given)) ok = true;
  }
  return ok;
}

export function otpauthUri(secretB32: string, label: string, issuer: string): string {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(label)}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
