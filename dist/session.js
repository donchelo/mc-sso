"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createSession = createSession;
exports.verifySession = verifySession;
const node_crypto_1 = require("node:crypto");
const DEFAULT_TTL_MS = 8 * 60 * 60 * 1000;
function sign(payload, secret) {
    return (0, node_crypto_1.createHmac)("sha256", secret).update(payload).digest("base64url");
}
function createSession(tenantId, secret, ttlMs = DEFAULT_TTL_MS) {
    const now = Date.now();
    const data = { tenantId, iat: now, exp: now + ttlMs };
    const payload = Buffer.from(JSON.stringify(data)).toString("base64url");
    return `${payload}.${sign(payload, secret)}`;
}
function verifySession(token, secret) {
    if (!token || !secret)
        return null;
    const dot = token.lastIndexOf(".");
    if (dot === -1)
        return null;
    const payload = token.slice(0, dot);
    const sig = token.slice(dot + 1);
    const expected = sign(payload, secret);
    try {
        const a = Buffer.from(sig, "base64url");
        const b = Buffer.from(expected, "base64url");
        if (a.length !== b.length || !(0, node_crypto_1.timingSafeEqual)(a, b))
            return null;
    }
    catch {
        return null;
    }
    try {
        const data = JSON.parse(Buffer.from(payload, "base64url").toString());
        if (typeof data.exp !== "number" || data.exp < Date.now())
            return null;
        return data;
    }
    catch {
        return null;
    }
}
