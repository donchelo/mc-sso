import { createHmac } from "node:crypto"

export function sign(payload: string, secret: string): string {
  if (!secret) throw new Error("sign: secret must not be empty")
  return createHmac("sha256", secret).update(payload).digest("base64url")
}
