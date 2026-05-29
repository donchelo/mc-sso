export interface McTokenPayload {
    tenantId: string;
    serviceId: string;
    displayName: string;
    exp: number;
}
export declare function createMcToken(tenantId: string, serviceId: string, displayName: string, secret: string): string;
export declare function verifyMcToken(token: string, serviceId: string, secret: string): McTokenPayload | null;
//# sourceMappingURL=token.d.ts.map