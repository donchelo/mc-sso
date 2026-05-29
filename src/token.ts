import { timingSafeEqual } from "node:crypto"
import { sign } from "./crypto"

export interface McTokenPayload {
  tenantId:    string
  serviceId:   string
  displayName: string
  exp:         number
}

export function createMcToken(
  tenantId:    string,
  serviceId:   string,
  displayName: string,
  secret:      string,
): string {
  const data: McTokenPayload = {
    tenantId,
    serviceId,
    displayName,
    exp: Date.now() + 5 * 60 * 1000,
  }
  const payload = Buffer.from(JSON.stringify(data)).toString("base64url")
  return `${payload}.${sign(payload, secret)}`
}

export function verifyMcToken(
  token:     string,
  serviceId: string,
  secret:    string,
): McTokenPayload | null {
  if (!token || !secret) return null
  const dot = token.lastIndexOf(".")
  if (dot === -1) return null
  const payload  = token.slice(0, dot)
  const sig      = token.slice(dot + 1)
  const expected = sign(payload, secret)
  try {
    const a = Buffer.from(sig,      "base64url")
    const b = Buffer.from(expected, "base64url")
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null
  } catch { return null }
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString()) as McTokenPayload
    if (
      typeof data.tenantId    !== "string" ||
      typeof data.serviceId   !== "string" ||
      typeof data.displayName !== "string" ||
      typeof data.exp         !== "number"
    ) return null
    if (data.exp < Date.now()) return null
    if (data.serviceId !== serviceId) return null
    return data
  } catch { return null }
}
