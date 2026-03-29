import type { Store } from "../types";

const DECAY_INTERVAL_MS = 60_000; // Decay 1 point every minute
const SCORE_TTL_MS = 24 * 60 * 60 * 1000; // Scores expire after 24 hours

export class IPScorer {
  private store: Store;
  private decayTimer: ReturnType<typeof setInterval>;

  constructor(store: Store) {
    this.store = store;
    this.decayTimer = setInterval(() => this.decayAll(), DECAY_INTERVAL_MS);
    if (this.decayTimer.unref) {
      this.decayTimer.unref();
    }
  }

  addScore(ip: string, points: number): number {
    const key = `ip:score:${ip}`;
    const trackKey = "ip:tracked";

    const current = this.store.get<number>(key) ?? 0;
    const newScore = Math.max(0, current + points);
    this.store.set(key, newScore, SCORE_TTL_MS);

    // Track IPs for decay
    const tracked = this.store.get<string[]>(trackKey) ?? [];
    if (!tracked.includes(ip)) {
      tracked.push(ip);
      this.store.set(trackKey, tracked, SCORE_TTL_MS);
    }

    return newScore;
  }

  getScore(ip: string): number {
    return this.store.get<number>(`ip:score:${ip}`) ?? 0;
  }

  private decayAll(): void {
    const tracked = this.store.get<string[]>("ip:tracked") ?? [];
    const remaining: string[] = [];

    for (const ip of tracked) {
      const key = `ip:score:${ip}`;
      const score = this.store.get<number>(key) ?? 0;
      if (score > 0) {
        this.store.set(key, score - 1, SCORE_TTL_MS);
        remaining.push(ip);
      }
    }

    if (remaining.length > 0) {
      this.store.set("ip:tracked", remaining, SCORE_TTL_MS);
    }
  }

  destroy(): void {
    clearInterval(this.decayTimer);
  }
}