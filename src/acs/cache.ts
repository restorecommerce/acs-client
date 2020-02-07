import {cfg} from '../config';
import logger from '../logger';
import * as crypto from 'crypto';

let attempted = false;
let redisInstance;
let ttl: number | undefined;
let globalPrefix: string | undefined;
let cacheEnabled = true;

let initializeCache = async () => {
  if (attempted || !cacheEnabled) {
    return;
  }

  attempted = true;

  let redis;

  try {
    redis = await import('redis');
  } catch (e) {
  }

  if (redis) {
    const redisConfig = cfg.get('authorization:cache');

    if (redisConfig) {
      redisConfig.db = cfg.get('authorization:cache:db-index');
      let redisClient = redis.createClient(redisConfig);
      ttl = cfg.get('authorization:cache:ttl');
      globalPrefix = cfg.get('authorization:cache:prefix');

      redisClient.on('error', err => {
        logger.error('Cache Error: ', err);
      });

      redisClient.ping((err: Error | null, reply: string) => {
        if (err) {
          logger.error('Failed to connect to ACS cache: ', err);
          return;
        }

        if (reply === 'PONG') {
          logger.info('ACS Connected to cache');
          redisInstance = redisClient;
        }
      });
    }
  }
};

initializeCache();

/**
 * Find the object in cache. If not found, compute it using the filler function
 *
 * @param keyData The data to base the cache key on
 * @param filler The function to execute if key is not found in cache
 * @param prefix The prefix to apply to the object key in the cache
 */
export const getOrFill = async <T, M>(keyData: T, filler: (data: T) => Promise<M>, prefix?: string): Promise<M | undefined> => {
  if (!redisInstance || !cacheEnabled) {
    return filler(keyData);
  }

  const inputHash = crypto.createHash('md5').update(JSON.stringify(keyData)).digest().toString('base64');
  let redisKey = `${inputHash}`;

  if (prefix) {
    redisKey = `${prefix}:` + redisKey;
  }

  return new Promise((resolve, reject) => {
    redisInstance.get(redisKey, async (err, reply) => {
      if (err) {
        logger.error('Failed fetching key from ACS cache: ', err);
        return;
      }

      if (reply) {
        logger.debug('Found key in cache: ' + redisKey);
        return resolve(JSON.parse(reply));
      }

      logger.debug('Filling cache key: ' + redisKey);

      return filler(keyData).then((data) => {
        if (data) {
          redisInstance.setex(redisKey, ttl, JSON.stringify(data));
        }

        resolve(data);
      }).catch(reject);
    });
  });
};

/**
 * Flush the ACS cache
 *
 * @param prefix An optional prefix to flush instead of entire cache
 */
export const flushCache = async (prefix?: string) => {
  if (!redisInstance || !cacheEnabled) {
    return;
  }

  if (prefix != undefined) {
    let flushPrefix = globalPrefix + prefix + '*';

    logger.debug('Flushing ACS cache prefix: ' + flushPrefix);

    return new Promise((resolve, reject) => {
      redisInstance.scan('0', 'MATCH', flushPrefix, (err, reply) => {
        if (err) {
          logger.error('Failed flushing ACS cache prefix: ', err);
          return reject();
        }

        if (reply.length >= 2 && reply[1].length > 0) {
          const cleaned = reply[1].map(key => globalPrefix ? key.substr(globalPrefix.length) : key);
          return redisInstance.del(cleaned, (err1, reply1) => {
            if (err1) {
              logger.error('Failed flushing ACS cache prefix: ', err1);
              return reject();
            }

            logger.debug('Flushed ACS cache prefix: ' + flushPrefix);
            return resolve();
          });
        }

        resolve();
      });
    });
  }

  logger.debug('Flushing ACS cache');

  return new Promise((resolve, reject) => {
    redisInstance.flushdb(async (err, reply) => {
      if (err) {
        logger.error('Failed flushing ACS cache: ', err);
        return reject();
      }

      if (reply) {
        logger.debug('Flushed ACS cache');
        return resolve();
      }
    });
  });
};

/**
 * Enable / Disable ACS Caching
 *
 * @param enabled Whether to enable or disable the cache
 */
export const setCacheStatus = (enabled: boolean) => {
  cacheEnabled = enabled;

  if (enabled) {
    logger.debug('ACS Cache Enabled');
    initializeCache();
  } else {
    logger.debug('ACS Cache Disabled');
  }
};
