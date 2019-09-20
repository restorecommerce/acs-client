import { initAuthZ, authZ } from './authz';

/**
 * Koa middleware using the BMSLSA implementation for `iam-authn`.
 */
export function acsClientMiddleware() {
  initAuthZ();

  return async (ctx: any, next) => {
    ctx.authZ = authZ;
    await next();
  };
}
