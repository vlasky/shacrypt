# shacrypt

[![npm version](https://img.shields.io/npm/v/@vlasky/shacrypt)](https://www.npmjs.com/package/@vlasky/shacrypt)
[![npm downloads](https://img.shields.io/npm/dm/@vlasky/shacrypt)](https://www.npmjs.com/package/@vlasky/shacrypt)
[![node version](https://img.shields.io/node/v/@vlasky/shacrypt)](https://nodejs.org/)
[![license](https://img.shields.io/npm/l/@vlasky/shacrypt)](LICENSE)
[![CI](https://github.com/vlasky/shacrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/vlasky/shacrypt/actions/workflows/ci.yml)

shacrypt provides SHA-256 crypt (`$5$`) and SHA-512 crypt (`$6$`) password hashing for Node.js, compatible with `crypt(3)` on Linux and the other Unix systems that use these schemes in `/etc/shadow`. The hashing itself is done by a native addon built around [Ulrich Drepper's reference C implementation](https://www.akkadia.org/drepper/SHA-crypt.txt), which is considerably faster than a JavaScript implementation. Salt generation and constant-time comparison use Node's own `crypto` module.

The addon is built with Node-API, so one compiled binary works across Node.js releases.

## Installation

```
npm install @vlasky/shacrypt
```

Prebuilt binaries are bundled for common platforms. Where none matches, the addon is compiled from source during installation, which needs a C/C++ toolchain:

- Linux: `gcc`/`g++` or `clang`, `make`, and Python 3 (for node-gyp)
- macOS: Xcode Command Line Tools (`xcode-select --install`)
- Windows: [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022) with the "Desktop development with C++" workload, and Python 3

Node.js 18 or later is required. TypeScript declarations are included.

## Usage

```javascript
// CommonJS
const shacrypt = require('@vlasky/shacrypt');

// ES modules
import { sha512cryptAsync, verifyAsync } from '@vlasky/shacrypt';
```

### Hashing a password

```javascript
const hash = await shacrypt.sha512cryptAsync('correct horse battery staple');
// '$6$rounds=5000$nKzXE5Cjk1uIhqN4$yE6R...'
```

A 16-character random salt is generated and the default of 5000 rounds is used. To choose the number of rounds:

```javascript
const hash = await shacrypt.sha512cryptAsync('correct horse battery staple', 100000);
// '$6$rounds=100000$...'
```

To supply your own salt, or a complete settings string:

```javascript
shacrypt.sha256crypt('password', 'my-salt');                 // '$5$rounds=5000$my-salt$...'
shacrypt.sha256crypt('password', 'my-salt', 10000);          // '$5$rounds=10000$my-salt$...'
shacrypt.sha256crypt('password', '$5$rounds=10000$my-salt'); // the same
```

### Verifying a password

```javascript
const ok = await shacrypt.verifyAsync(candidate, storedHash);
```

`verify()` and `verifyAsync()` work out the algorithm from the hash's prefix, hash the candidate with the stored salt and rounds, and compare the result in constant time using `crypto.timingSafeEqual()`. Do not compare hashes with `===`; that leaks timing information.

A hash with a very large rounds value takes a correspondingly long time to verify. If stored hashes come from an untrusted source, cap the work you are prepared to do:

```javascript
await shacrypt.verifyAsync(candidate, storedHash, { maxRounds: 500000 });
// throws a RangeError instead of hashing if storedHash asks for more rounds
```

### Synchronous, callback and Promise forms

The hashing functions have a synchronous form, a callback form, and a Promise form; `verify()` has a synchronous form and a Promise form. The synchronous forms block the event loop for the duration of the hash, which at 5000 rounds is on the order of a millisecond, and much longer at higher round counts. The callback and Promise forms run the hash on the libuv thread pool.

```javascript
// Synchronous
const hash = shacrypt.sha256crypt(password, salt, rounds);
const ok = shacrypt.verify(password, hash);

// Callback: the callback may be the second, third or fourth argument
shacrypt.sha256crypt(password, (error, hash) => { ... });
shacrypt.sha256crypt(password, salt, (error, hash) => { ... });
shacrypt.sha256crypt(password, salt, rounds, (error, hash) => { ... });

// Promise
const hash = await shacrypt.sha256cryptAsync(password, salt, rounds);
const ok = await shacrypt.verifyAsync(password, hash);
```

Argument errors are thrown synchronously in every form, including the callback form, as Node's own `crypto` functions do. Promise forms reject.

The thread pool is shared with Node's file system, DNS and `crypto` operations and has four threads by default (see `UV_THREADPOOL_SIZE`). Each queued hash holds a copy of its password in memory until it runs, so an application that accepts hashing requests from the network should limit how many it has in flight.

## API

### `sha256crypt(password, [salt], [rounds], [callback])` and `sha512crypt(...)`

| Argument | Description |
|---|---|
| `password` | A string of at most 511 bytes of UTF-8 with no NUL characters. |
| `salt` | Optional. A raw salt, a settings string such as `$6$rounds=10000$salt`, or an existing hash, whose salt and rounds are reused. A raw salt may contain any printable ASCII characters other than `$ : ; * !` and `\` and is truncated to 16 characters, as `crypt(3)` does. A random 16-character salt is generated when omitted. A number here is taken as `rounds`. |
| `rounds` | Optional. An integer between 1000 and 999,999,999. Defaults to 5000. If the salt is a settings string that already specifies rounds, this must match it. |
| `callback` | Optional `(error, hash)`. When present the hash is computed on the thread pool and nothing is returned. |

Returns the hash string in synchronous mode. Throws a `TypeError` or `RangeError` for invalid arguments.

### `sha256cryptAsync(password, [salt], [rounds])` and `sha512cryptAsync(...)`

The same, returning a Promise for the hash.

### `verify(password, hash, [options])` and `verifyAsync(password, hash, [options])`

Returns `true` if `password` produces `hash`, otherwise `false`. A password that could never have produced a valid hash, because it contains a NUL character or exceeds 511 bytes, gives `false`. Throws a `TypeError` if `hash` is not a well-formed SHA-256 crypt or SHA-512 crypt hash, and a `RangeError` if `options.maxRounds` is set and the hash's rounds exceed it.

### `constants`

A frozen object with `ROUNDS_DEFAULT` (5000), `ROUNDS_MIN` (1000), `ROUNDS_MAX` (999999999), `SALT_LENGTH_MAX` (16) and `PASSWORD_MAX_BYTES` (511).

## Limits and compatibility notes

- The 511-byte password limit matches libxcrypt, whose limit of 512 includes the terminating NUL, so every password this library accepts can also be checked by `crypt(3)`.
- Salt validation matches libxcrypt, which refuses `: ; * !` and `\` anywhere in a settings string, so every hash this library produces can be verified by `crypt(3)`. An empty raw salt is refused, and a salt this library generates is always 16 characters, but an empty salt in a settings string or stored hash is accepted, because `crypt(3)` produces such hashes. The limit exists because the algorithm's cost grows with the square of the password length.
- The output format follows the specification exactly, so hashes interoperate with glibc, libxcrypt, Python's `crypt` and `passlib`, and the specification's own test vectors are part of the test suite.
- Rounds specified inside a settings string are clamped to the 1000 to 999,999,999 range as the specification requires. Rounds passed as an argument must already be inside the range.
- Passwords are wiped from native memory once hashing completes. JavaScript strings cannot be wiped.

## Development

```
npm install      # builds the addon
npm test         # rebuilds, then runs the Mocha suite
npm run prebuildify   # produces a prebuilt binary under prebuilds/
```

## Authors

- Vlad Lasky, https://github.com/vlasky
- Oleksiy Krivoshey, https://github.com/oleksiyk
- Original C code by Ulrich Drepper, https://www.akkadia.org/drepper/SHA-crypt.txt

## License (MIT)

Copyright (c) 2013-2016 Oleksiy Krivoshey.  
Copyright (c) 2018-2026 Vlad Lasky.

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
