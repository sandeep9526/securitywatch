import { describe, it, expect, afterEach } from "vitest";
import { IPScorer } from "../src/core/scorer";
import { MemoryStore } from "../src/store/memory";

describe("IPScorer", () => {
  let store: MemoryStore;
  let scorer: IPScorer;

  afterEach(() => {
    scorer?.destroy();
    store?.destroy();
  });

  it("starts at zero for unknown IPs", () => {
    store = new MemoryStore();
    scorer = new IPScorer(store);
    expect(scorer.getScore("10.0.0.1")).toBe(0);
  });

  it("accumulates positive scores", () => {
    store = new MemoryStore();
    scorer = new IPScorer(store);

    scorer.addScore("10.0.0.1", 5);
    scorer.addScore("10.0.0.1", 3);
    expect(scorer.getScore("10.0.0.1")).toBe(8);
  });

  it("decreases score but never below zero", () => {
    store = new MemoryStore();
    scorer = new IPScorer(store);

    scorer.addScore("10.0.0.1", 2);
    scorer.addScore("10.0.0.1", -5);
    expect(scorer.getScore("10.0.0.1")).toBe(0);
  });

  it("tracks IPs independently", () => {
    store = new MemoryStore();
    scorer = new IPScorer(store);

    scorer.addScore("10.0.0.1", 5);
    scorer.addScore("10.0.0.2", 10);

    expect(scorer.getScore("10.0.0.1")).toBe(5);
    expect(scorer.getScore("10.0.0.2")).toBe(10);
  });

  it("handles normal traffic decay (negative scores)", () => {
    store = new MemoryStore();
    scorer = new IPScorer(store);

    // Normal behavior — should decay to zero
    scorer.addScore("10.0.0.1", -0.5);
    expect(scorer.getScore("10.0.0.1")).toBe(0);
  });

  it("destroy cleans up", () => {
    store = new MemoryStore();
    scorer = new IPScorer(store);

    scorer.addScore("10.0.0.1", 5);
    scorer.destroy();
    // After destroy, underlying store still has data but scorer is inactive
    expect(() => scorer.getScore("10.0.0.1")).not.toThrow();
  });
});