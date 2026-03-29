import type { Store } from "../types.js";

const DECAY_INTERVAL_MS = 60_000;
const SCORE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_TRACKED_IPS = 10_000;

export class IPScorer {
  private store: Store;
  private trackedIPs = new Set<string>();
  private decayTimer: ReturnType<typeof setInterval>;

  constructor(store: Store) {
    this.store = store;
    this.decayTimer = setInterval(() => this.decayAll(), DECAY_INTERVAL_MS);
    if (this.decayTimer.unref) this.decayTimer.unref();
  }

  addScore(ip: string, points: number): number {
    const key = `ip:score:${ip}`;
    const current = this.store.get<number>(key) ?? 0;
    const newScore = Math.max(0, current + points);
    this.store.set(key, newScore, SCORE_TTL_MS);

    if (newScore > 0 && this.trackedIPs.size < MAX_TRACKED_IPS) {
      this.trackedIPs.add(ip);
    } else if (newScore === 0) {
      this.trackedIPs.delete(ip);
    }
    return newScore;
  }

  getScore(ip: string): number {
    return this.store.get<number>(`ip:score:${ip}`) ?? 0;
  }

  private decayAll(): void {
    for (const ip of this.trackedIPs) {
      const key = `ip:score:${ip}`;
      const score = this.store.get<number>(key) ?? 0;
      if (score > 0) {
        this.store.set(key, score - 1, SCORE_TTL_MS);
      } else {
        this.trackedIPs.delete(ip);
      }
    }
  }

  destroy(): void {
    clearInterval(this.decayTimer);
    this.trackedIPs.clear();
  }
}