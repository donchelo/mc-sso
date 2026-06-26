import { describe, it, expect, vi, beforeEach } from "vitest"
import { createMcToken, verifyMcToken } from "../src/token"

const SECRET  = "test-secret-key"
const TENANT  = "tamaprint"
const SERVICE = "sapb1chat"
const DISPLAY = "Tamaprint"

describe("createMcToken / verifyMcToken", () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"))
  })

  it("round-trip: verify returns original payload", () => {
    const token  = createMcToken(TENANT, SERVICE, DISPLAY, SECRET)
    const result = verifyMcToken(token, SERVICE, SECRET)
    expect(result).not.toBeNull()
    expect(result!.tenantId).toBe(TENANT)
    expect(result!.serviceId).toBe(SERVICE)
    expect(result!.displayName).toBe(DISPLAY)
  })

  it("rejects altered signature", () => {
    const token    = createMcToken(TENANT, SERVICE, DISPLAY, SECRET)
    const tampered = token.slice(0, -4) + "XXXX"
    expect(verifyMcToken(tampered, SERVICE, SECRET)).toBeNull()
  })

  it("rejects expired token (> 5 min)", () => {
    const token = createMcToken(TENANT, SERVICE, DISPLAY, SECRET)
    vi.advanceTimersByTime(6 * 60 * 1000)
    expect(verifyMcToken(token, SERVICE, SECRET)).toBeNull()
  })

  it("accepts token just before 5 min", () => {
    const token = createMcToken(TENANT, SERVICE, DISPLAY, SECRET)
    vi.advanceTimersByTime(4 * 60 * 1000 + 59_000)
    expect(verifyMcToken(token, SERVICE, SECRET)).not.toBeNull()
  })

  it("embebe y devuelve identidad+permisos (userId/roles/allowedModules)", () => {
    const token = createMcToken(TENANT, SERVICE, DISPLAY, SECRET, {
      userId: "u-123",
      roles: ["admin"],
      allowedModules: ["kpis", "pulse"],
    })
    const result = verifyMcToken(token, SERVICE, SECRET)
    expect(result).not.toBeNull()
    expect(result!.userId).toBe("u-123")
    expect(result!.roles).toEqual(["admin"])
    expect(result!.allowedModules).toEqual(["kpis", "pulse"])
  })

  it("retrocompatible: sin extra, los campos quedan undefined", () => {
    const token = createMcToken(TENANT, SERVICE, DISPLAY, SECRET)
    const result = verifyMcToken(token, SERVICE, SECRET)
    expect(result!.userId).toBeUndefined()
    expect(result!.allowedModules).toBeUndefined()
  })

  it("rejects wrong serviceId", () => {
    const token = createMcToken(TENANT, SERVICE, DISPLAY, SECRET)
    expect(verifyMcToken(token, "other-service", SECRET)).toBeNull()
  })

  it("rejects wrong secret", () => {
    const token = createMcToken(TENANT, SERVICE, DISPLAY, SECRET)
    expect(verifyMcToken(token, SERVICE, "wrong-secret")).toBeNull()
  })

  it("returns null for empty token", () => {
    expect(verifyMcToken("", SERVICE, SECRET)).toBeNull()
  })

  it("returns null for malformed token (no dot)", () => {
    expect(verifyMcToken("nodothere", SERVICE, SECRET)).toBeNull()
  })
})
