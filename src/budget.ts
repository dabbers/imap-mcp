// Exfiltration budgets: sized for how an assistant actually uses mail (a few searches,
// a few bodies per question), not for a client that wants to dump the mailbox.
// Windows are sliding, in-memory, global (there is exactly one user). Counters reset on
// container restart, which an attacker holding only a token cannot cause.

export interface BudgetConfig {
  callsPerMin: number;       // any tool call
  searchesPerHour: number;
  bodiesPerHour: number;     // get_message that returns a body
  bodiesPerDay: number;
  distinctBodiesPerDay: number; // unique uids read per day (re-reading the same mail is cheap)
  tripwireRejects: number;   // rejected calls within an hour before the token is revoked
}

class Window {
  private t: number[] = [];
  constructor(private ms: number) {}
  private prune(now: number) { while (this.t.length && this.t[0] <= now - this.ms) this.t.shift(); }
  count(now = Date.now()) { this.prune(now); return this.t.length; }
  hit(now = Date.now()) { this.prune(now); if (this.t.length < 10_000) this.t.push(now); }
  clear() { this.t = []; }
  resetAt(now = Date.now()) { this.prune(now); return this.t.length ? new Date(this.t[0] + this.ms) : new Date(now); }
}

export class BudgetExceeded extends Error {
  constructor(public what: string, public resetAt: Date) {
    super(`Budget exhausted: ${what}. Resets at ${resetAt.toISOString()}. This connector is deliberately rate-limited; do not retry in a loop.`);
  }
}

export class Budget {
  private calls = new Window(60_000);
  private searches = new Window(3_600_000);
  private bodiesH = new Window(3_600_000);
  private bodiesD = new Window(86_400_000);
  private rejects = new Window(3_600_000);
  private seen = new Map<string, number>(); // "folder:uid" -> first-read ts (24h)
  tripped = false;

  constructor(private cfg: BudgetConfig, private onTrip: () => void) {}

  private reject(what: string, resetAt: Date): never {
    if (!this.tripped) this.rejects.hit();
    if (!this.tripped && this.rejects.count() >= this.cfg.tripwireRejects) {
      this.tripped = true;
      this.onTrip();
    }
    throw new BudgetExceeded(what, resetAt);
  }

  call() {
    if (this.tripped) this.reject("tripwire: too many over-budget calls; re-authorize with a fresh TOTP", new Date(Date.now() + 3_600_000));
    if (this.calls.count() >= this.cfg.callsPerMin) this.reject(`${this.cfg.callsPerMin} calls/min`, this.calls.resetAt());
    this.calls.hit();
  }

  search() {
    if (this.searches.count() >= this.cfg.searchesPerHour) this.reject(`${this.cfg.searchesPerHour} searches/hour`, this.searches.resetAt());
    this.searches.hit();
  }

  /** Call before downloading a body. Re-reads of a uid seen today don't count against distinct. */
  body(key: string) {
    const now = Date.now();
    for (const [k, t] of this.seen) if (t <= now - 86_400_000) this.seen.delete(k);
    if (this.bodiesH.count() >= this.cfg.bodiesPerHour) this.reject(`${this.cfg.bodiesPerHour} message reads/hour`, this.bodiesH.resetAt());
    if (this.bodiesD.count() >= this.cfg.bodiesPerDay) this.reject(`${this.cfg.bodiesPerDay} message reads/day`, this.bodiesD.resetAt());
    if (!this.seen.has(key) && this.seen.size >= this.cfg.distinctBodiesPerDay) {
      this.reject(`${this.cfg.distinctBodiesPerDay} distinct messages/day`, new Date(Math.min(...this.seen.values()) + 86_400_000));
    }
    this.bodiesH.hit(now); this.bodiesD.hit(now);
    if (!this.seen.has(key)) this.seen.set(key, now);
  }

  /** After a fresh TOTP: clear the trip and the reject history, and give the new session a
   *  clean hourly window so its first call doesn't re-trip on the abuser's leftovers. The daily
   *  and distinct-uid caps stay, so re-auth cannot be used to raise the exfiltration ceiling. */
  untrip() { this.tripped = false; this.rejects.clear(); this.bodiesH.clear(); this.searches.clear(); this.calls.clear(); }

  snapshot() {
    return {
      callsThisMinute: this.calls.count(), searchesThisHour: this.searches.count(),
      bodiesThisHour: this.bodiesH.count(), bodiesToday: this.bodiesD.count(), distinctToday: this.seen.size,
      tripped: this.tripped,
    };
  }
}
