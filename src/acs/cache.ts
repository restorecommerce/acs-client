import {cfg} from '../config';
import logger from '../logger';
import * as crypto from 'crypto';

let attempted = false;
let redisInstance;
let ttl: number | undefined;

let initRedis = async () => {
  if (attempted) {
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

initRedis();


export const getOrFill = async <T, M>(keyData: T, filler: (data: T) => Promise<M>, prefix?: string): Promise<M | undefined> => {
  if (!redisInstance) {
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

export const flushCache = async () => {
  if (!redisInstance) {
    return;
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
