# Changelog

## [0.6.0] - 2026-11-01

### Security
- **Fixed a data race in the asynchronous functions.** The C code wrote every result into a shared static buffer, so concurrent async calls could return another call's hash, a truncated hash, or read freed memory. The native layer now calls the reentrant `sha256_crypt_r()` and `sha512_crypt_r()` with a per-call buffer and the shared entry points are gone.
- Passwords are limited to 511 bytes of UTF-8 (`constants.PASSWORD_MAX_BYTES`). Hashing cost grows with the square of the password length, so an unbounded password was a denial-of-service vector. 511 is the largest password libxcrypt accepts.
- `rounds` is validated: it must be a safe integer between 1000 and 999,999,999. Previously a negative value was clamped to 999,999,999 rounds and ran for minutes, and a fractional value became part of the salt.
- Passwords and salts containing a NUL character are rejected instead of being silently truncated at the NUL.
- Salts are validated: printable ASCII other than `$ : ; * !` and `\`, the characters libxcrypt refuses. Non-ASCII salts could be truncated mid-character and produce a hash that did not verify against itself. An empty raw salt is refused, but an empty salt inside a settings string or stored hash is accepted, as `crypt(3)` does.
- Working buffers in the C code are heap-allocated instead of using `alloca()`, which could overflow a thread-pool stack, and are wiped with stores the compiler cannot optimise away. The password copy held by the native layer is wiped after use.
- Generated salts now draw from the full 64-character crypt alphabet (96 bits) rather than hexadecimal (64 bits).

### Added
- `verify(password, hash, [options])` and `verifyAsync()`: detect the algorithm from the hash, compare in constant time with `crypto.timingSafeEqual()`, and optionally refuse hashes whose rounds exceed `options.maxRounds`.
- A callback may now be passed as the second or third argument, not only the fourth. Previously `sha256crypt(password, salt, callback)` ran synchronously and never called the callback.
- Passing `rounds` with a settings string that has none now applies the rounds. A conflicting `rounds` throws instead of being silently ignored.
- `constants` export with the library's limits.
- `exports` map and an ES module import test.
- GitHub Actions CI across Linux, macOS and Windows on Node.js 18, 20, 22 and 24, and a prebuild workflow that bundles prebuilt binaries on release.

### Changed
- **Breaking:** migrated from NAN to Node-API (`node-addon-api`), with `node-gyp-build` as the loader. One binary now works across Node.js releases and prebuilt binaries can be shipped.
- **Breaking:** invalid arguments now throw `TypeError` or `RangeError` with specific messages, where they previously produced a hash with surprising settings. Boxed `String` objects are no longer accepted as passwords.
- **Breaking:** a settings string for the other algorithm (for example `$6$...` passed to `sha256crypt()`) throws instead of producing an empty-salt hash.
- Tests use `node:assert` instead of Chai, which was ESM-only and failed on Node.js 18, and Mocha configuration moved from the ignored `test/mocha.opts` to `.mocharc.json`. The suite now covers concurrency, every argument form, and every validation rule.
- `npm test` rebuilds the addon first, so it can no longer test a stale binary.
- `package.json` gains a `files` allowlist; the published package no longer includes tests and development files.
- `binding.gyp` no longer references a non-existent `deps/libmagic` include path and its compiler flags are inside the target where node-gyp reads them.
- README rewritten; the Windows build instructions now point at current Visual Studio Build Tools.

## [0.5.1] - 2026-01-29

### Added
- TypeScript type declarations (`index.d.ts`)

## [0.5.0] - 2026-01-28

### Changed
- **Breaking:** Minimum Node.js version is now 18.0.0
- Updated NAN to 2.25.0 for Node.js 25 compatibility
- Updated mocha to 11.3.0 and chai to 6.2.2
- Replaced `NODE_MODULE` with `NAN_MODULE_WORKER_ENABLED` for proper module registration
- Fixed null pointer subtraction warnings in sha256crypt.c and sha512crypt.c using `uintptr_t`

### Added
- Support for Node.js 25

## [0.4.0] - 2025-06-27

### Added
- New ES6 async/await compatible functions: `sha256cryptAsync()` and `sha512cryptAsync()`
- These functions return Promises and can be used with modern async/await syntax
- Full test coverage for the new async functions

### Changed
- Updated documentation to include examples of the new async/await API

## [0.3.0] - 2025-06-14

### Added
- Input validation and error handling to prevent crashes
- Support for Node.js 16-23

## [0.2.0] - 2019-12-16

### Added
- Asynchronous support through optional callback functions
- Windows build compatibility improvements
- Cross-platform portability enhancements

### Changed
- Updated nan to latest version 2.14.0 to make it work under Node.js v12
- Replaced endian.h with portable_endian.h for better cross-platform support

## Previous versions

See git history for older changes.