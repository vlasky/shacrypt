/**
 * Callback for the callback-based forms. On failure `error` is set and `hash`
 * is undefined.
 */
export type HashCallback = (error: Error | null, hash?: string) => void;

/**
 * Options for verify() and verifyAsync().
 */
export interface VerifyOptions {
  /**
   * Refuse (by throwing a RangeError) to verify a hash whose rounds exceed
   * this value. By default any rounds the specification allows (up to
   * 999,999,999) are honoured.
   */
  maxRounds?: number;
}

/**
 * Limits applied by this library.
 */
export const constants: Readonly<{
  /** Rounds used when none are given: 5000. */
  ROUNDS_DEFAULT: number;
  /** Smallest permitted rounds value: 1000. */
  ROUNDS_MIN: number;
  /** Largest permitted rounds value: 999,999,999. */
  ROUNDS_MAX: number;
  /** Salts longer than this (16) are truncated. */
  SALT_LENGTH_MAX: number;
  /** Passwords longer than this many UTF-8 bytes (511) are rejected. */
  PASSWORD_MAX_BYTES: number;
}>;

/**
 * Generate a SHA-256 crypt hash synchronously.
 *
 * @param password - The password to hash (at most 511 bytes of UTF-8, no NUL)
 * @param salt - A raw salt (printable ASCII other than $ : ; * ! and \\, truncated to 16 characters), a
 *   settings string such as `$5$rounds=10000$salt`, or an existing hash.
 *   Generated when omitted.
 * @param rounds - Rounds between 1000 and 999,999,999 (default 5000)
 */
export function sha256crypt(password: string, salt?: string | null, rounds?: number | null): string;
/** Generate a SHA-256 crypt hash synchronously with a generated salt and the given rounds. */
export function sha256crypt(password: string, rounds: number): string;
/** Generate a SHA-256 crypt hash on the thread pool. Argument errors throw synchronously. */
export function sha256crypt(password: string, callback: HashCallback): void;
export function sha256crypt(password: string, salt: string | null | undefined, callback: HashCallback): void;
export function sha256crypt(password: string, rounds: number, callback: HashCallback): void;
export function sha256crypt(
  password: string,
  salt: string | null | undefined,
  rounds: number | null | undefined,
  callback: HashCallback
): void;

/**
 * Generate a SHA-512 crypt hash synchronously. Same forms as sha256crypt().
 */
export function sha512crypt(password: string, salt?: string | null, rounds?: number | null): string;
export function sha512crypt(password: string, rounds: number): string;
export function sha512crypt(password: string, callback: HashCallback): void;
export function sha512crypt(password: string, salt: string | null | undefined, callback: HashCallback): void;
export function sha512crypt(password: string, rounds: number, callback: HashCallback): void;
export function sha512crypt(
  password: string,
  salt: string | null | undefined,
  rounds: number | null | undefined,
  callback: HashCallback
): void;

/**
 * Generate a SHA-256 crypt hash on the thread pool, returning a Promise.
 * Argument errors reject the Promise.
 */
export function sha256cryptAsync(password: string, salt?: string | null, rounds?: number | null): Promise<string>;
export function sha256cryptAsync(password: string, rounds: number): Promise<string>;

/**
 * Generate a SHA-512 crypt hash on the thread pool, returning a Promise.
 */
export function sha512cryptAsync(password: string, salt?: string | null, rounds?: number | null): Promise<string>;
export function sha512cryptAsync(password: string, rounds: number): Promise<string>;

/**
 * Check a password against a stored SHA-256 crypt or SHA-512 crypt hash
 * using a constant-time comparison.
 *
 * Returns false for a wrong password, including one that could never have
 * produced a hash (embedded NUL, over the length limit). Throws a TypeError
 * for a non-string password or a malformed hash, and a RangeError if
 * options.maxRounds is exceeded.
 */
export function verify(password: string, hash: string, options?: VerifyOptions): boolean;

/**
 * verify() on the thread pool, returning a Promise.
 */
export function verifyAsync(password: string, hash: string, options?: VerifyOptions): Promise<boolean>;
