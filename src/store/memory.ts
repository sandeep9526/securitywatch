import type { Store, StoreEntry } from "../types";

export class MemoryStore implements Store {
  private data = new Map<string, StoreEntry>();
  private cleanupInterval: ReturnType<typeof setInterval>;

  constructor(cleanupIntervalMs = 60_000) {
    this.cleanupInterval = setInterval(() => this.cleanup(), cleanupIntervalMs);
    // Allow Node to exit even if interval is running
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }

  get<T = unknown>(key: string): T | undefined {
    const entry = this.data.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.data.delete(key);
      return undefined;
    }
    return entry.value as T;
  }

  set<T = unknown>(key: string, value: T, ttlMs: number): void {
    this.data.set(key, { value, expiresAt: Date.now() + ttlMs });
  }

  increment(key: string, ttlMs: number): number {
    const current = this.get<number>(key) ?? 0;
    const next = current + 1;
    this.set(key, next, ttlMs);
    return next;
  }

  delete(key: string): void {
    this.data.delete(key);
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.data) {
      if (now > entry.expiresAt) {
        this.data.delete(key);
      }
    }
  }

  destroy(): void {
    clearInterval(this.cleanupInterval);
    this.data.clear();
  }
}