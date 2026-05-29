import { describe, it, expect, vi, beforeEach } from "vitest"
import { createSession, verifySession } from "../src/session"

const SECRET = "test-secret-key"
const TENANT = "flexoimpresos"

describe("createSession / verifySession", () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"))
  })

  it("round-trip: returns tenantId", () => {
    const token  = createSession(TENANT, SECRET)
    const result = verifySession(token, SECRET)
    expect(result).not.toBeNull()
    expect(result!.tenantId).toBe(TENANT)
  })

  it("rejects after default TTL (8 h)", () => {
    const token = createSession(TENANT, SECRET)
    vi.advanceTimersByTime(8 * 60 * 60 * 1000 + 1)
    expect(verifySession(token, SECRET)).toBeNull()
  })

  it("respects custom TTL", () => {
    const token = createSession(TENANT, SECRET, 60_000)
    vi.advanceTimersByTime(61_000)
    expect(verifySession(token, SECRET)).toBeNull()
  })

  it("accepts token just before expiry", () => {
    const token = createSession(TENANT, SECRET, 60_000)
    vi.advanceTimersByTime(59_000)
    expect(verifySession(token, SECRET)).not.toBeNull()
  })

  it("rejects tampered signature", () => {
    const token    = createSession(TENANT, SECRET)
    const tampered = token.slice(0, -4) + "XXXX"
    expect(verifySession(tampered, SECRET)).toBeNull()
  })

  it("rejects wrong secret", () => {
    const token = createSession(TENANT, SECRET)
    expect(verifySession(token, "wrong-secret")).toBeNull()
  })

  it("returns null for empty token", () => {
    expect(verifySession("", SECRET)).toBeNull()
  })
})
