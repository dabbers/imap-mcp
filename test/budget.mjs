import { Budget, BudgetExceeded } from "../dist/budget.js";
let fails = 0; const check = (n, ok, x = "") => { console.log(`${ok ? "PASS" : "FAIL"}  ${n} ${x}`); if (!ok) fails++; };
let tripped = 0;
const b = new Budget({ callsPerMin: 5, searchesPerHour: 3, bodiesPerHour: 4, bodiesPerDay: 6, distinctBodiesPerDay: 3, tripwireRejects: 3 }, () => tripped++);
const tryc = (f) => { try { f(); return null; } catch (e) { return e; } };

for (let i = 0; i < 5; i++) b.call();
check("6th call/min rejected", tryc(() => b.call()) instanceof BudgetExceeded);
const b2 = new Budget({ callsPerMin: 100, searchesPerHour: 3, bodiesPerHour: 4, bodiesPerDay: 6, distinctBodiesPerDay: 3, tripwireRejects: 3 }, () => tripped++);
b2.body("INBOX:1"); b2.body("INBOX:2"); b2.body("INBOX:1"); // re-read doesn't count as distinct
check("re-read same uid not distinct", b2.snapshot().distinctToday === 2);
b2.body("INBOX:3");
check("4th distinct/day rejected", tryc(() => b2.body("INBOX:4")) instanceof BudgetExceeded);
check("re-read of seen uid still blocked by hourly cap (4 used)", tryc(() => b2.body("INBOX:1")) instanceof BudgetExceeded);
check("tripwire not yet", tripped === 0);
tryc(() => b2.body("INBOX:9"));
check("tripwire after 3 rejects revokes token", tripped === 1 && b2.tripped);
check("after trip every call is refused", String(tryc(() => b2.call())?.message).includes("tripwire"));
b2.untrip();
check("fresh TOTP clears trip", tryc(() => b2.call()) === null);
const e = tryc(() => b2.body("INBOX:9"));
check("error text tells the model not to loop", /do not retry in a loop/.test(e?.message ?? ""));
process.exit(fails ? 1 : 0);
