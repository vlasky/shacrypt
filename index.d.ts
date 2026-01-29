/**
 * Callback function for async hash operations.
 */
type HashCallback = (error: Error | null, hash: string) => void;

/**
 * Generate SHA256-CRYPT hash (synchronous).
 *
 * @param password - The password to hash
 * @param salt - Optional salt string (auto-generated if not provided)
 * @param rounds - Optional number of rounds (default: 5000, minimum: 1000)
 * @returns The hashed password string
 */
export function sha256crypt(password: string, salt?: string, rounds?: number): string;

/**
 * Generate SHA256-CRYPT hash (callback-based async).
 *
 * @param password - The password to hash
 * @param salt - Optional salt string (auto-generated if not provided)
 * @param rounds - Optional number of rounds (default: 5000, minimum: 1000)
 * @param callback - Callback function receiving (error, hash)
 */
export function sha256crypt(password: string, salt: string | undefined, rounds: number | undefined, callback: HashCallback): void;

/**
 * Generate SHA512-CRYPT hash (synchronous).
 *
 * @param password - The password to hash
 * @param salt - Optional salt string (auto-generated if not provided)
 * @param rounds - Optional number of rounds (default: 5000, minimum: 1000)
 * @returns The hashed password string
 */
export function sha512crypt(password: string, salt?: string, rounds?: number): string;

/**
 * Generate SHA512-CRYPT hash (callback-based async).
 *
 * @param password - The password to hash
 * @param salt - Optional salt string (auto-generated if not provided)
 * @param rounds - Optional number of rounds (default: 5000, minimum: 1000)
 * @param callback - Callback function receiving (error, hash)
 */
export function sha512crypt(password: string, salt: string | undefined, rounds: number | undefined, callback: HashCallback): void;

/**
 * Generate SHA256-CRYPT hash (async/await compatible).
 *
 * @param password - The password to hash
 * @param salt - Optional salt string (auto-generated if not provided)
 * @param rounds - Optional number of rounds (default: 5000, minimum: 1000)
 * @returns Promise resolving to the hashed password string
 */
export function sha256cryptAsync(password: string, salt?: string, rounds?: number): Promise<string>;

/**
 * Generate SHA512-CRYPT hash (async/await compatible).
 *
 * @param password - The password to hash
 * @param salt - Optional salt string (auto-generated if not provided)
 * @param rounds - Optional number of rounds (default: 5000, minimum: 1000)
 * @returns Promise resolving to the hashed password string
 */
export function sha512cryptAsync(password: string, salt?: string, rounds?: number): Promise<string>;
