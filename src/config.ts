import * as sconfig from '@restorecommerce/service-config';
// Export cfg Object
export const cfg = sconfig(process.cwd());
// errors mapped to code and message
export const errors = cfg.get('errors');
export const jwtSecret = cfg.get('graphql:jwtSecret');
