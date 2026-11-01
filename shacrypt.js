'use strict';

const crypto = require('crypto');
const util = require('util');

/**
 * Callback for the callback-based forms. On failure `error` is set and `hash`
 * is undefined.
 * @typedef {(error: Error | null, hash?: string) => void} HashCallback
 */

/**
 * Options accepted by verify() and verifyAsync().
 * @typedef {{ maxRounds?: number }} VerifyOptions
 */

/**
 * The native functions. The async ones always pass a hash on success.
 * @typedef {object} Binding
 * @property {(password: string, settings: string) => string} sha256crypt
 * @property {(password: string, settings: string) => string} sha512crypt
 * @property {(password: string, settings: string, callback: (error: Error | null, hash: string) => void) => void} sha256cryptasync
 * @property {(password: string, settings: string, callback: (error: Error | null, hash: string) => void) => void} sha512cryptasync
 */

/**
 * One of the two supported algorithms.
 * @typedef {object} Algorithm
 * @property {string} prefix The `$5$` or `$6$` identifier.
 * @property {number} hashLength Length of the encoded hash part.
 * @property {(password: string, settings: string) => string} sync
 * @property {(password: string, settings: string, callback: HashCallback) => void} withCallback
 * @property {(password: string, settings: string) => Promise<string>} promise
 */

/** @type {Binding} */
const binding = require('node-gyp-build')(__dirname);

// Limits from Ulrich Drepper's SHA-crypt specification.
const ROUNDS_DEFAULT = 5000;
const ROUNDS_MIN = 1000;
const ROUNDS_MAX = 999999999;
const SALT_LENGTH_MAX = 16;

// Upper bound on the password, in UTF-8 bytes. The algorithm's cost grows
// quadratically with the password length, so an unbounded password is a
// denial-of-service vector. libxcrypt's CRYPT_MAX_PASSPHRASE_SIZE is 512
// including the terminating NUL, so 511 is the largest password that the
// system crypt(3) will also accept.
const PASSWORD_MAX_BYTES = 511;

// The crypt(3) base64 alphabet, used for generated salts and hash output.
const SALT_ALPHABET = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

// A salt may contain printable ASCII other than '$' (the field separator)
// and the characters libxcrypt refuses in any settings string: ':' ';' '*'
// '!' and '\\'. Non-ASCII salts are refused because the C code truncates salts
// by byte, which can split a multi-byte character and produce a hash that
// does not verify against itself.
const SALT_INVALID = /[^\x21-\x7e]|[$:;*!\\]/;
const HASH_CHARS = /^[./0-9A-Za-z]+$/;

/** @type {{ sha256: Algorithm, sha512: Algorithm }} */
const ALGORITHMS = {
  sha256: {
    prefix: '$5$',
    hashLength: 43,
    sync: binding.sha256crypt,
    withCallback: binding.sha256cryptasync,
    promise: util.promisify(binding.sha256cryptasync),
  },
  sha512: {
    prefix: '$6$',
    hashLength: 86,
    sync: binding.sha512crypt,
    withCallback: binding.sha512cryptasync,
    promise: util.promisify(binding.sha512cryptasync),
  },
};

/** @type {Record<string, Algorithm>} */
const BY_PREFIX = {
  [ALGORITHMS.sha256.prefix]: ALGORITHMS.sha256,
  [ALGORITHMS.sha512.prefix]: ALGORITHMS.sha512,
};

/** @returns {string} A random 16-character salt from the crypt alphabet. */
function generateSalt() {
  // 256 is a multiple of 64, so masking each byte gives an unbiased choice.
  const bytes = crypto.randomBytes(SALT_LENGTH_MAX);
  let salt = '';
  for (const byte of bytes) {
    salt += SALT_ALPHABET[byte & 63];
  }
  return salt;
}

/**
 * @param {number} rounds
 * @returns {number}
 */
function clampRounds(rounds) {
  return Math.min(Math.max(rounds, ROUNDS_MIN), ROUNDS_MAX);
}

/**
 * @param {unknown} password
 * @returns {asserts password is string}
 */
function validatePassword(password) {
  if (typeof password !== 'string') {
    throw new TypeError('password must be a String');
  }
  if (password.includes('\0')) {
    throw new TypeError('password must not contain NUL characters');
  }
  if (Buffer.byteLength(password, 'utf8') > PASSWORD_MAX_BYTES) {
    throw new RangeError(`password must be at most ${PASSWORD_MAX_BYTES} bytes of UTF-8`);
  }
}

/**
 * @param {unknown} rounds
 * @returns {number}
 */
function validateRounds(rounds) {
  if (typeof rounds !== 'number' || !Number.isSafeInteger(rounds)) {
    throw new TypeError('rounds must be an integer');
  }
  if (rounds < ROUNDS_MIN || rounds > ROUNDS_MAX) {
    throw new RangeError(`rounds must be between ${ROUNDS_MIN} and ${ROUNDS_MAX}`);
  }
  return rounds;
}

// Validates a salt and truncates it to 16 characters, as crypt(3) does. An
// empty salt is refused for new hashes but allowed inside a settings string
// or stored hash, since crypt(3) accepts it and such hashes exist.
/**
 * @param {string} salt
 * @param {boolean} allowEmpty
 * @returns {string}
 */
function validateSalt(salt, allowEmpty) {
  if (salt.length === 0 && !allowEmpty) {
    throw new TypeError('salt must not be empty');
  }
  if (SALT_INVALID.test(salt)) {
    throw new TypeError("salt may only contain printable ASCII characters other than $ : ; * ! and \\");
  }
  return salt.slice(0, SALT_LENGTH_MAX);
}

// Parses a settings string or complete hash: "$5$[rounds=N$]salt[$hash]".
// The rounds digits are returned as written so that the C code applies the
// specification's clamping to them exactly as crypt(3) would. The fields are
// taken strictly left to right, exactly as the C parser does, so JavaScript
// and C can never disagree about which part is the rounds and which the salt.
/**
 * @param {Algorithm} algo
 * @param {string} settings
 * @returns {{ rounds: string | undefined, salt: string, hash: string | undefined }}
 */
function parseSettings(algo, settings) {
  if (!settings.startsWith(algo.prefix)) {
    const other = Object.keys(BY_PREFIX).find((prefix) => settings.startsWith(prefix));
    if (other) {
      throw new TypeError(`salt is a ${other} settings string but a ${algo.prefix} hash was requested`);
    }
    throw new TypeError(`settings string must start with ${algo.prefix}`);
  }
  let rest = settings.slice(algo.prefix.length);
  let rounds;
  if (rest.startsWith('rounds=')) {
    const match = /^rounds=(\d+)\$/.exec(rest);
    if (!match) {
      throw new TypeError('malformed rounds field in settings string');
    }
    rounds = match[1];
    rest = rest.slice(match[0].length);
  }
  const separator = rest.indexOf('$');
  const salt = separator === -1 ? rest : rest.slice(0, separator);
  const hash = separator === -1 ? undefined : rest.slice(separator + 1);
  return { rounds, salt, hash };
}

// Builds the settings string handed to the native code from the caller's salt
// and rounds arguments. A missing salt is generated. A raw salt always gets an
// explicit rounds field, matching previous releases. A settings string or hash
// is passed through with its own rounds unless the caller supplies a
// conflicting value.
/**
 * @param {Algorithm} algo
 * @param {unknown} salt
 * @param {unknown} rounds
 * @returns {string}
 */
function buildSettings(algo, salt, rounds) {
  const explicit = rounds === undefined || rounds === null ? undefined : validateRounds(rounds);

  if (salt === undefined || salt === null) {
    return `${algo.prefix}rounds=${explicit === undefined ? ROUNDS_DEFAULT : explicit}$${generateSalt()}`;
  }
  if (typeof salt !== 'string') {
    throw new TypeError('salt must be a String');
  }

  if (salt.startsWith('$')) {
    const parsed = parseSettings(algo, salt);
    const cleanSalt = validateSalt(parsed.salt, true);
    if (parsed.rounds !== undefined) {
      if (explicit !== undefined && explicit !== clampRounds(Number(parsed.rounds))) {
        throw new RangeError('rounds argument conflicts with the rounds in the settings string');
      }
      return `${algo.prefix}rounds=${parsed.rounds}$${cleanSalt}`;
    }
    if (explicit === undefined) {
      return `${algo.prefix}${cleanSalt}`;
    }
    return `${algo.prefix}rounds=${explicit}$${cleanSalt}`;
  }

  return `${algo.prefix}rounds=${explicit === undefined ? ROUNDS_DEFAULT : explicit}$${validateSalt(salt, false)}`;
}

// Accepts the documented shorthand forms: a callback as the last argument in
// any position after the password, and a number in place of the salt.
/**
 * @param {unknown} password
 * @param {unknown} salt
 * @param {unknown} rounds
 * @param {unknown} callback
 * @returns {{ password: unknown, salt: unknown, rounds: unknown, callback: unknown }}
 */
function normaliseArguments(password, salt, rounds, callback) {
  if (typeof salt === 'function') {
    callback = salt;
    salt = undefined;
    rounds = undefined;
  } else if (typeof rounds === 'function') {
    callback = rounds;
    rounds = undefined;
  }
  if (typeof salt === 'number') {
    if (rounds !== undefined && rounds !== null) {
      throw new TypeError('rounds given both as the second and third argument');
    }
    rounds = salt;
    salt = undefined;
  }
  return { password, salt, rounds, callback };
}

// Argument errors are thrown synchronously even in callback mode, as Node's
// own crypto functions do. Only failures inside the native code reach the
// callback's error argument.
/**
 * @param {Algorithm} algo
 * @param {[unknown, unknown, unknown, unknown]} args
 * @returns {string | undefined}
 */
function hash(algo, args) {
  const { password, salt, rounds, callback } = normaliseArguments(...args);
  if (callback !== undefined && callback !== null && typeof callback !== 'function') {
    throw new TypeError('callback must be a function');
  }
  validatePassword(password);
  const settings = buildSettings(algo, salt, rounds);
  if (typeof callback === 'function') {
    algo.withCallback(password, settings, /** @type {HashCallback} */ (callback));
    return undefined;
  }
  return algo.sync(password, settings);
}

/**
 * @param {Algorithm} algo
 * @param {[unknown, unknown, unknown, unknown]} args
 * @returns {Promise<string>}
 */
async function hashAsync(algo, args) {
  const { password, salt, rounds, callback } = normaliseArguments(...args);
  if (callback !== undefined) {
    throw new TypeError('the Promise-returning functions do not take a callback');
  }
  validatePassword(password);
  const settings = buildSettings(algo, salt, rounds);
  return algo.promise(password, settings);
}

// Validates a stored hash and rebuilds the settings string from its parsed
// fields, so that the native code is only ever handed what was validated.
/**
 * @param {unknown} hashString
 * @returns {{ algo: Algorithm, rounds: number, settings: string }}
 */
function parseHash(hashString) {
  if (typeof hashString !== 'string') {
    throw new TypeError('hash must be a String');
  }
  const invalid = () => new TypeError('hash is not a valid SHA-256 crypt or SHA-512 crypt hash');
  const algo = BY_PREFIX[hashString.slice(0, 3)];
  if (!algo) {
    throw invalid();
  }
  const parsed = parseSettings(algo, hashString);
  if (parsed.hash === undefined || parsed.hash.length !== algo.hashLength || !HASH_CHARS.test(parsed.hash)
    || parsed.salt.length > SALT_LENGTH_MAX || SALT_INVALID.test(parsed.salt)) {
    throw invalid();
  }
  const rounds = parsed.rounds === undefined ? ROUNDS_DEFAULT : clampRounds(Number(parsed.rounds));
  const settings = parsed.rounds === undefined
    ? `${algo.prefix}${parsed.salt}`
    : `${algo.prefix}rounds=${parsed.rounds}$${parsed.salt}`;
  return { algo, rounds, settings };
}

// Shared by verify() and verifyAsync(). Type errors and policy violations
// throw. A password that could never have produced a valid hash (embedded
// NUL, over the length limit) is simply a wrong password.
/**
 * @param {unknown} password
 * @param {unknown} hashString
 * @param {unknown} options
 * @returns {{ algo: Algorithm, settings: string, acceptable: boolean }}
 */
function prepareVerify(password, hashString, options) {
  const { algo, rounds, settings } = parseHash(hashString);
  if (typeof password !== 'string') {
    throw new TypeError('password must be a String');
  }
  const maxRounds = typeof options === 'object' && options !== null
    ? /** @type {{ maxRounds?: unknown }} */ (options).maxRounds
    : undefined;
  if (maxRounds !== undefined) {
    const limit = validateRounds(maxRounds);
    if (rounds > limit) {
      throw new RangeError(`hash uses ${rounds} rounds, more than the maxRounds limit of ${limit}`);
    }
  }
  const acceptable = !password.includes('\0') && Buffer.byteLength(password, 'utf8') <= PASSWORD_MAX_BYTES;
  return { algo, settings, acceptable };
}

/**
 * @param {string} computed
 * @param {string} expected
 * @returns {boolean}
 */
function constantTimeEqual(computed, expected) {
  const a = Buffer.from(computed, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/**
 * @overload
 * @param {string} password
 * @param {string | null} [salt]
 * @param {number | null} [rounds]
 * @returns {string}
 */
/**
 * @overload
 * @param {string} password
 * @param {number} rounds
 * @returns {string}
 */
/**
 * @overload
 * @param {string} password
 * @param {HashCallback} callback
 * @returns {void}
 */
/**
 * @overload
 * @param {string} password
 * @param {string | null | undefined} salt
 * @param {HashCallback} callback
 * @returns {void}
 */
/**
 * @overload
 * @param {string} password
 * @param {number} rounds
 * @param {HashCallback} callback
 * @returns {void}
 */
/**
 * @overload
 * @param {string} password
 * @param {string | null | undefined} salt
 * @param {number | null | undefined} rounds
 * @param {HashCallback} callback
 * @returns {void}
 */
/**
 * Generate a SHA-256 crypt hash.
 *
 * sha256crypt(password, [salt], [rounds], [callback])
 * sha256crypt(password, rounds, [callback])
 *
 * Without a callback the hash is returned. With a callback the work runs on
 * the libuv thread pool and the callback receives (error, hash).
 *
 * @param {string} password
 * @param {string | number | HashCallback | null} [salt] A raw salt, a settings string, an existing hash, the rounds, or the callback.
 * @param {number | HashCallback | null} [rounds]
 * @param {HashCallback} [callback]
 * @returns {string | undefined} The hash, or undefined in callback mode.
 */
function sha256crypt(password, salt, rounds, callback) {
  return hash(ALGORITHMS.sha256, [password, salt, rounds, callback]);
}

/**
 * @overload
 * @param {string} password
 * @param {string | null} [salt]
 * @param {number | null} [rounds]
 * @returns {string}
 */
/**
 * @overload
 * @param {string} password
 * @param {number} rounds
 * @returns {string}
 */
/**
 * @overload
 * @param {string} password
 * @param {HashCallback} callback
 * @returns {void}
 */
/**
 * @overload
 * @param {string} password
 * @param {string | null | undefined} salt
 * @param {HashCallback} callback
 * @returns {void}
 */
/**
 * @overload
 * @param {string} password
 * @param {number} rounds
 * @param {HashCallback} callback
 * @returns {void}
 */
/**
 * @overload
 * @param {string} password
 * @param {string | null | undefined} salt
 * @param {number | null | undefined} rounds
 * @param {HashCallback} callback
 * @returns {void}
 */
/**
 * Generate a SHA-512 crypt hash. Same forms as sha256crypt().
 *
 * @param {string} password
 * @param {string | number | HashCallback | null} [salt]
 * @param {number | HashCallback | null} [rounds]
 * @param {HashCallback} [callback]
 * @returns {string | undefined}
 */
function sha512crypt(password, salt, rounds, callback) {
  return hash(ALGORITHMS.sha512, [password, salt, rounds, callback]);
}

/**
 * @overload
 * @param {string} password
 * @param {string | null} [salt]
 * @param {number | null} [rounds]
 * @returns {Promise<string>}
 */
/**
 * @overload
 * @param {string} password
 * @param {number} rounds
 * @returns {Promise<string>}
 */
/**
 * Generate a SHA-256 crypt hash on the thread pool, returning a Promise.
 *
 * @param {string} password
 * @param {string | number | null} [salt]
 * @param {number | null} [rounds]
 * @returns {Promise<string>}
 */
function sha256cryptAsync(password, salt, rounds) {
  return hashAsync(ALGORITHMS.sha256, [password, salt, rounds, undefined]);
}

/**
 * @overload
 * @param {string} password
 * @param {string | null} [salt]
 * @param {number | null} [rounds]
 * @returns {Promise<string>}
 */
/**
 * @overload
 * @param {string} password
 * @param {number} rounds
 * @returns {Promise<string>}
 */
/**
 * Generate a SHA-512 crypt hash on the thread pool, returning a Promise.
 *
 * @param {string} password
 * @param {string | number | null} [salt]
 * @param {number | null} [rounds]
 * @returns {Promise<string>}
 */
function sha512cryptAsync(password, salt, rounds) {
  return hashAsync(ALGORITHMS.sha512, [password, salt, rounds, undefined]);
}

/**
 * Check a password against a stored SHA-256 crypt or SHA-512 crypt hash
 * using a constant-time comparison. Throws if the hash is malformed, or if
 * options.maxRounds is given and the hash's rounds exceed it.
 *
 * @param {string} password
 * @param {string} hashString
 * @param {VerifyOptions} [options]
 * @returns {boolean}
 */
function verify(password, hashString, options) {
  const { algo, settings, acceptable } = prepareVerify(password, hashString, options);
  if (!acceptable) {
    return false;
  }
  return constantTimeEqual(algo.sync(password, settings), hashString);
}

/**
 * verify() on the thread pool, returning a Promise.
 *
 * @param {string} password
 * @param {string} hashString
 * @param {VerifyOptions} [options]
 * @returns {Promise<boolean>}
 */
async function verifyAsync(password, hashString, options) {
  const { algo, settings, acceptable } = prepareVerify(password, hashString, options);
  if (!acceptable) {
    return false;
  }
  return constantTimeEqual(await algo.promise(password, settings), hashString);
}

const constants = Object.freeze({
  ROUNDS_DEFAULT,
  ROUNDS_MIN,
  ROUNDS_MAX,
  SALT_LENGTH_MAX,
  PASSWORD_MAX_BYTES,
});

module.exports = {
  sha256crypt,
  sha512crypt,
  sha256cryptAsync,
  sha512cryptAsync,
  verify,
  verifyAsync,
  constants,
};
