/**
 * Initialize ACS Cache
 */
export declare const initializeCache: () => Promise<void>;
/**
 * Find the object in cache. If not found, compute it using the filler function
 *
 * @param keyData The data to base the cache key on
 * @param filler The function to execute if key is not found in cache
 * @param prefix The prefix to apply to the object key in the cache
 */
export declare const getOrFill: <T, M>(keyData: T, filler: (data: T) => Promise<M>, prefix?: string) => Promise<M>;
/**
 * Flush the ACS cache
 *
 * @param prefix An optional prefix to flush instead of entire cache
 */
export declare const flushCache: (prefix?: string) => Promise<unknown>;
/**
 * Enable / Disable ACS Caching
 *
 * @param enabled Whether to enable or disable the cache
 */
export declare const setCacheStatus: (enabled: boolean) => void;
