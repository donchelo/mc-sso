"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createMcToken = createMcToken;
exports.verifyMcToken = verifyMcToken;
const node_crypto_1 = require("node:crypto");
function sign(payload, secret) {
    return (0, node_crypto_1.createHmac)("sha256", secret).update(payload).digest("base64url");
}
function createMcToken(tenantId, serviceId, displayName, secret) {
    const data = {
        tenantId,
        serviceId,
        displayName,
        exp: Date.now() + 5 * 60 * 1000,
    };
    const payload = Buffer.from(JSON.stringify(data)).toString("base64url");
    return `${payload}.${sign(payload, secret)}`;
}
function verifyMcToken(token, serviceId, secret) {
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
        if (data.exp < Date.now())
            return null;
        if (data.serviceId !== serviceId)
            return null;
        return data;
    }
    catch {
        return null;
    }
}
