/**
 * Koa middleware using the BMSLSA implementation for `iam-authn`.
 */
export declare const acsClientMiddleware: (config?: any) => (ctx: any, next: any) => Promise<void>;
