import { Logger } from '@restorecommerce/logger';
import { cfg } from './config';

export default new Logger(cfg.get('logger'));
