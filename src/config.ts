import * as sconfig from '@restorecommerce/service-config';
// Export cfg Object
export let cfg = sconfig(process.cwd());
// errors mapped to code and message
export const errors = cfg.get('errors');

export const updateConfig = (config: any) => {
  cfg = config;
};
