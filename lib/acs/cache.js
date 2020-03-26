"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const config_1 = require("../config");
const logger_1 = require("../logger");
const crypto = require("crypto");
let attempted = false;
let redisInstance;
let ttl;
let globalPrefix;
let cacheEnabled = true;
/**
 * Initialize ACS Cache
 */
exports.initializeCache = () => __awaiter(void 0, void 0, void 0, function* () {
    if (attempted || !cacheEnabled) {
        return;
    }
    attempted = true;
    let redis;
    try {
        redis = yield Promise.resolve().then(() => require('redis'));
    }
    catch (e) {
    }
    if (redis) {
        const redisConfig = config_1.cfg.get('authorization:cache');
        if (redisConfig) {
            redisConfig.db = config_1.cfg.get('authorization:cache:db-index');
            redisInstance = redis.createClient(redisConfig);
            ttl = config_1.cfg.get('authorization:cache:ttl');
            globalPrefix = config_1.cfg.get('authorization:cache:prefix');
        }
    }
});
/**
 * Find the object in cache. If not found, compute it using the filler function
 *
 * @param keyData The data to base the cache key on
 * @param filler The function to execute if key is not found in cache
 * @param prefix The prefix to apply to the object key in the cache
 */
exports.getOrFill = (keyData, filler, prefix) => __awaiter(void 0, void 0, void 0, function* () {
    if (!redisInstance || !cacheEnabled) {
        return filler(keyData);
    }
    const inputHash = crypto.createHash('md5').update(JSON.stringify(keyData)).digest().toString('base64');
    let redisKey = `${inputHash}`;
    if (prefix) {
        redisKey = `${prefix}:` + redisKey;
    }
    return new Promise((resolve, reject) => {
        redisInstance.get(redisKey, (err, reply) => __awaiter(void 0, void 0, void 0, function* () {
            if (err) {
                logger_1.default.error('Failed fetching key from ACS cache: ', err);
                return;
            }
            if (reply) {
                logger_1.default.debug('Found key in cache: ' + redisKey);
                return resolve(JSON.parse(reply));
            }
            logger_1.default.debug('Filling cache key: ' + redisKey);
            return filler(keyData).then((data) => {
                if (data) {
                    if (ttl) {
                        redisInstance.setex(redisKey, ttl, JSON.stringify(data));
                    }
                    else {
                        redisInstance.set(redisKey, JSON.stringify(data));
                    }
                }
                resolve(data);
            }).catch(reject);
        }));
    });
});
/**
 * Flush the ACS cache
 *
 * @param prefix An optional prefix to flush instead of entire cache
 */
exports.flushCache = (prefix) => __awaiter(void 0, void 0, void 0, function* () {
    if (!redisInstance || !cacheEnabled) {
        return;
    }
    if (prefix != undefined) {
        let flushPrefix = globalPrefix + prefix + '*';
        logger_1.default.debug('Flushing ACS cache prefix: ' + flushPrefix);
        return new Promise((resolve, reject) => {
            redisInstance.scan('0', 'MATCH', flushPrefix, (err, reply) => {
                if (err) {
                    logger_1.default.error('Failed flushing ACS cache prefix: ', err);
                    return reject();
                }
                if (reply.length >= 2 && reply[1].length > 0) {
                    const cleaned = reply[1].map(key => globalPrefix ? key.substr(globalPrefix.length) : key);
                    return redisInstance.del(cleaned, (err1, reply1) => {
                        if (err1) {
                            logger_1.default.error('Failed flushing ACS cache prefix: ', err1);
                            return reject();
                        }
                        logger_1.default.debug('Flushed ACS cache prefix: ' + flushPrefix);
                        return resolve();
                    });
                }
                resolve();
            });
        });
    }
    logger_1.default.debug('Flushing ACS cache');
    return new Promise((resolve, reject) => {
        redisInstance.flushdb((err, reply) => __awaiter(void 0, void 0, void 0, function* () {
            if (err) {
                logger_1.default.error('Failed flushing ACS cache: ', err);
                return reject();
            }
            if (reply) {
                logger_1.default.debug('Flushed ACS cache');
                return resolve();
            }
        }));
    });
});
/**
 * Enable / Disable ACS Caching
 *
 * @param enabled Whether to enable or disable the cache
 */
exports.setCacheStatus = (enabled) => {
    cacheEnabled = enabled;
    if (enabled) {
        logger_1.default.debug('ACS Cache Enabled');
        exports.initializeCache();
    }
    else {
        logger_1.default.debug('ACS Cache Disabled');
    }
};
