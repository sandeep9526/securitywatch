import { describe, it, expect } from "vitest";
import { MemoryStore } from "../src/store/memory";

describe("MemoryStore", () => {
  it("stores and retrieves values", () => {
    const store = new MemoryStore();
    store.set("key1", "value1", 60_000);
    expect(store.get("key1")).toBe("value1");
    store.destroy();
  });

  it("returns undefined for missing keys", () => {
    const store = new MemoryStore();
    expect(store.get("nonexistent")).toBeUndefined();
    store.destroy();
  });

  it("increments values", () => {
    const store = new MemoryStore();
    expect(store.increment("counter", 60_000)).toBe(1);
    expect(store.increment("counter", 60_000)).toBe(2);
    expect(store.increment("counter", 60_000)).toBe(3);
    store.destroy();
  });

  it("deletes values", () => {
    const store = new MemoryStore();
    store.set("key2", "value2", 60_000);
    store.delete("key2");
    expect(store.get("key2")).toBeUndefined();
    store.destroy();
  });

  it("expires values after TTL", async () => {
    const store = new MemoryStore();
    store.set("short", "data", 50); // 50ms TTL
    expect(store.get("short")).toBe("data");

    await new Promise((r) => setTimeout(r, 100));
    expect(store.get("short")).toBeUndefined();
    store.destroy();
  });

  it("handles complex objects", () => {
    const store = new MemoryStore();
    const obj = { name: "test", scores: [1, 2, 3] };
    store.set("complex", obj, 60_000);
    expect(store.get("complex")).toEqual(obj);
    store.destroy();
  });
});