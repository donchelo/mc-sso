export interface SessionPayload {
    tenantId: string;
    iat: number;
    exp: number;
}
export declare function createSession(tenantId: string, secret: string, ttlMs?: number): string;
export declare function verifySession(token: string, secret: string): SessionPayload | null;
//# sourceMappingURL=session.d.ts.map