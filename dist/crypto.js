"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sign = sign;
const node_crypto_1 = require("node:crypto");
function sign(payload, secret) {
    if (!secret)
        throw new Error("sign: secret must not be empty");
    return (0, node_crypto_1.createHmac)("sha256", secret).update(payload).digest("base64url");
}
