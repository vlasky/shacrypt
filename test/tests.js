'use strict';

const assert = require('node:assert/strict');
const shacrypt = require('../shacrypt');

const { sha256crypt, sha512crypt, sha256cryptAsync, sha512cryptAsync, verify, verifyAsync, constants } = shacrypt;

// Test vectors from Ulrich Drepper's specification, https://www.akkadia.org/drepper/SHA-crypt.txt
const vectors256 = [
  ['$5$saltstring', 'Hello world!',
    '$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5'],
  ['$5$rounds=10000$saltstringsaltstring', 'Hello world!',
    '$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA'],
  ['$5$rounds=5000$toolongsaltstring', 'This is just a test',
    '$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5'],
  ['$5$rounds=1400$anotherlongsaltstring',
    'a very much longer text to encrypt.  This one even stretches over morethan one line.',
    '$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1'],
  ['$5$rounds=77777$short', 'we have a short salt string but not a short password',
    '$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/'],
  ['$5$rounds=123456$asaltof16chars..', 'a short string',
    '$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD'],
  ['$5$rounds=10$roundstoolow', 'the minimum number is still observed',
    '$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC'],
];

const vectors512 = [
  ['$6$saltstring', 'Hello world!',
    '$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1'],
  ['$6$rounds=10000$saltstringsaltstring', 'Hello world!',
    '$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.'],
  ['$6$rounds=5000$toolongsaltstring', 'This is just a test',
    '$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0'],
  ['$6$rounds=1400$anotherlongsaltstring',
    'a very much longer text to encrypt.  This one even stretches over morethan one line.',
    '$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1'],
  ['$6$rounds=77777$short', 'we have a short salt string but not a short password',
    '$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0'],
  ['$6$rounds=123456$asaltof16chars..', 'a short string',
    '$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1'],
  ['$6$rounds=10$roundstoolow', 'the minimum number is still observed',
    '$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.'],
];

const algorithms = [
  { name: 'sha256', prefix: '$5$', escaped: '\\$5\\$', vectors: vectors256, sync: sha256crypt, promise: sha256cryptAsync, hashLength: 43 },
  { name: 'sha512', prefix: '$6$', escaped: '\\$6\\$', vectors: vectors512, sync: sha512crypt, promise: sha512cryptAsync, hashLength: 86 },
];

const fromCallback = (fn, ...args) => new Promise((resolve, reject) => {
  fn(...args, (error, result) => (error ? reject(error) : resolve(result)));
});

for (const algo of algorithms) {
  describe(`${algo.name}: specification test vectors`, function () {
    for (const [settings, password, expected] of algo.vectors) {
      it(`sync: ${settings}`, function () {
        assert.equal(algo.sync(password, settings), expected);
      });
      it(`callback: ${settings}`, async function () {
        assert.equal(await fromCallback(algo.sync, password, settings, undefined), expected);
      });
      it(`promise: ${settings}`, async function () {
        assert.equal(await algo.promise(password, settings), expected);
      });
    }
  });

  describe(`${algo.name}: concurrency`, function () {
    // Regression test for the shared static output buffer in the original C
    // code, which returned other requests' hashes under concurrent load.
    it('600 concurrent async calls all return the right hash', async function () {
      const jobs = Array.from({ length: 600 }, (_, i) => [`password-${i}`, `${algo.prefix}rounds=1000$salt${i}`]);
      const expected = jobs.map(([password, settings]) => algo.sync(password, settings));
      const actual = await Promise.all(jobs.map(([password, settings]) => algo.promise(password, settings)));
      assert.deepEqual(actual, expected);
    });

    it('sync and async calls interleaved agree', async function () {
      const pending = Array.from({ length: 50 }, (_, i) => algo.promise('pw', `${algo.prefix}rounds=1000$s${i}`));
      const syncResults = Array.from({ length: 50 }, (_, i) => algo.sync('pw', `${algo.prefix}rounds=1000$s${i}`));
      assert.deepEqual(await Promise.all(pending), syncResults);
    });
  });

  describe(`${algo.name}: argument forms`, function () {
    it('generates a salt when none is given', function () {
      const hash = algo.sync('password');
      assert.match(hash, new RegExp(`^${algo.escaped}rounds=5000\\$[./0-9A-Za-z]{16}\\$[./0-9A-Za-z]{${algo.hashLength}}$`));
    });

    it('generated salts differ', function () {
      assert.notEqual(algo.sync('password'), algo.sync('password'));
    });

    it('accepts a number as the second argument as the rounds', function () {
      assert.match(algo.sync('password', 1234), new RegExp(`^${algo.escaped}rounds=1234\\$`));
      assert.match(algo.sync('password', null, 1234), new RegExp(`^${algo.escaped}rounds=1234\\$`));
    });

    it('rejects rounds given twice', function () {
      assert.throws(() => algo.sync('password', 1234, 5678), TypeError);
    });

    it('uses a raw salt with the default rounds', function () {
      assert.match(algo.sync('password', 'my-salt'), new RegExp(`^${algo.escaped}rounds=5000\\$my-salt\\$`));
    });

    it('truncates a raw salt to 16 characters', function () {
      assert.match(algo.sync('password', 'abcdefghijklmnopqrstuvwxyz'), new RegExp(`^${algo.escaped}rounds=5000\\$abcdefghijklmnop\\$`));
    });

    it('calls a callback given as the second argument', async function () {
      const hash = await fromCallback(algo.sync, 'password');
      assert.match(hash, new RegExp(`^${algo.escaped}rounds=5000\\$`));
    });

    it('calls a callback given as the third argument', async function () {
      const hash = await fromCallback(algo.sync, 'password', 'salt');
      assert.match(hash, new RegExp(`^${algo.escaped}rounds=5000\\$salt\\$`));
      const withRounds = await fromCallback(algo.sync, 'password', 1500);
      assert.match(withRounds, new RegExp(`^${algo.escaped}rounds=1500\\$`));
    });

    it('calls a callback given as the fourth argument', async function () {
      const hash = await fromCallback(algo.sync, 'password', 'salt', 1500);
      assert.match(hash, new RegExp(`^${algo.escaped}rounds=1500\\$salt\\$`));
    });

    it('returns undefined in callback mode', function (done) {
      assert.equal(algo.sync('password', 'salt', done), undefined);
    });

    it('rejects a non-function fourth argument', function () {
      assert.throws(() => algo.sync('password', 'salt', 1000, 'callback'), TypeError);
    });

    it('promise form rejects a callback', async function () {
      await assert.rejects(algo.promise('password', () => {}), TypeError);
    });
  });

  describe(`${algo.name}: password validation`, function () {
    it('rejects a non-string password', function () {
      assert.throws(() => algo.sync(123, 'salt'), /password must be a String/);
      assert.throws(() => algo.sync(null, 'salt'), /password must be a String/);
      assert.throws(() => algo.sync(), /password must be a String/);
      assert.throws(() => algo.sync(new String('boxed'), 'salt'), /password must be a String/);
    });

    it('throws synchronously in callback mode', function () {
      assert.throws(() => algo.sync(123, 'salt', () => assert.fail('callback must not be called')), /password must be a String/);
    });

    it('rejects asynchronously in promise mode', async function () {
      await assert.rejects(algo.promise(123, 'salt'), /password must be a String/);
    });

    it('rejects an embedded NUL rather than truncating', function () {
      assert.throws(() => algo.sync('abc\0def', 'salt'), /NUL/);
    });

    it('accepts an empty password', function () {
      assert.match(algo.sync('', 'salt'), new RegExp(`^${algo.escaped}`));
    });

    it('enforces the byte limit on the UTF-8 encoding', function () {
      // libxcrypt's limit of 512 includes the terminating NUL
      assert.equal(constants.PASSWORD_MAX_BYTES, 511);
      assert.doesNotThrow(() => algo.sync('a'.repeat(511), `${algo.prefix}rounds=1000$salt`));
      assert.throws(() => algo.sync('a'.repeat(512), 'salt'), RangeError);
      // 'é' is two bytes
      assert.doesNotThrow(() => algo.sync('é'.repeat(255), `${algo.prefix}rounds=1000$salt`));
      assert.throws(() => algo.sync('é'.repeat(256), 'salt'), RangeError);
    });
  });

  describe(`${algo.name}: rounds validation`, function () {
    it('rejects negative rounds (previously ran 999,999,999 rounds)', function () {
      assert.throws(() => algo.sync('password', 'salt', -5), RangeError);
    });

    it('rejects rounds below the minimum and above the maximum', function () {
      assert.throws(() => algo.sync('password', 'salt', 999), RangeError);
      assert.throws(() => algo.sync('password', 'salt', 1000000000), RangeError);
      assert.doesNotThrow(() => algo.sync('password', `${algo.prefix}rounds=1000$salt`, 1000));
    });

    it('rejects fractional, NaN, Infinity, zero and string rounds', function () {
      assert.throws(() => algo.sync('password', 'salt', 1.5), TypeError);
      assert.throws(() => algo.sync('password', 'salt', NaN), TypeError);
      assert.throws(() => algo.sync('password', 'salt', Infinity), TypeError);
      assert.throws(() => algo.sync('password', 'salt', 0), RangeError);
      assert.throws(() => algo.sync('password', 'salt', '1000'), TypeError);
    });

    it('treats null rounds as the default', function () {
      assert.match(algo.sync('password', 'salt', null), new RegExp(`^${algo.escaped}rounds=5000\\$`));
    });
  });

  describe(`${algo.name}: salt and settings validation`, function () {
    it('rejects a non-string salt', function () {
      assert.throws(() => algo.sync('password', {}), TypeError);
    });

    it('rejects an empty raw salt', function () {
      assert.throws(() => algo.sync('password', ''), TypeError);
    });

    it('accepts an empty salt inside a settings string, as crypt(3) does', function () {
      const hash = algo.sync('password', `${algo.prefix}rounds=1000$`);
      assert.match(hash, new RegExp(`^${algo.escaped}rounds=1000\\$\\$`));
      assert.equal(verify('password', hash), true);
      assert.match(algo.sync('password', algo.prefix), new RegExp(`^${algo.escaped}\\$`));
    });

    it('rejects non-ASCII, whitespace, control characters and $ : ; * ! \\ in a salt', function () {
      for (const bad of ['a'.repeat(15) + 'é', 'bad salt', 'tab\tsalt', 'new\nline', 'a$b', 'a:b', 'a;b', 'a*b', 'salt!', 'a\\b']) {
        assert.throws(() => algo.sync('password', bad), TypeError, JSON.stringify(bad));
        if (!bad.includes('$')) {
          // inside a settings string '$' is the field separator, so only the others apply
          assert.throws(() => algo.sync('password', `${algo.prefix}rounds=1000$${bad}`), TypeError, JSON.stringify(bad));
        }
      }
    });

    it('accepts the punctuation libxcrypt accepts in a raw salt', function () {
      assert.doesNotThrow(() => algo.sync('password', `${algo.prefix}rounds=1000$my-salt_./,#@`));
    });

    it('rejects a settings string for the other algorithm', function () {
      const other = algo.prefix === '$5$' ? '$6$' : '$5$';
      assert.throws(() => algo.sync('password', `${other}rounds=1000$salt`), /settings string but/);
    });

    it('rejects an unknown prefix', function () {
      assert.throws(() => algo.sync('password', '$1$salt'), /must start with/);
    });

    it('rejects a malformed rounds field', function () {
      assert.throws(() => algo.sync('password', `${algo.prefix}rounds=1.5$salt`), /malformed rounds/);
      assert.throws(() => algo.sync('password', `${algo.prefix}rounds=abc$salt`), /malformed rounds/);
      assert.throws(() => algo.sync('password', `${algo.prefix}rounds=1000salt`), /malformed rounds/);
    });

    it('applies an explicit rounds argument to a settings string without one', function () {
      assert.match(algo.sync('password', `${algo.prefix}salt`, 2000), new RegExp(`^${algo.escaped}rounds=2000\\$salt\\$`));
    });

    it('accepts an explicit rounds argument equal to the embedded one', function () {
      assert.match(algo.sync('password', `${algo.prefix}rounds=2000$salt`, 2000), new RegExp(`^${algo.escaped}rounds=2000\\$salt\\$`));
      // embedded rounds below the minimum are clamped by the specification
      assert.doesNotThrow(() => algo.sync('password', `${algo.prefix}rounds=10$salt`, 1000));
    });

    it('rejects an explicit rounds argument that conflicts with the embedded one', function () {
      assert.throws(() => algo.sync('password', `${algo.prefix}rounds=2000$salt`, 3000), RangeError);
    });

    it('uses only the salt portion of a complete hash', function () {
      const [settings, password, expected] = algo.vectors[1];
      assert.equal(algo.sync(password, expected), expected);
      assert.equal(algo.sync(password, settings), expected);
    });
  });
}

describe('verify', function () {
  const hash256 = sha256crypt('correct horse', '$5$rounds=1000$salt');
  const hash512 = sha512crypt('correct horse', '$6$rounds=1000$salt');
  const plain256 = sha256crypt('correct horse', '$5$salt');

  it('accepts the right password for both algorithms', function () {
    assert.equal(verify('correct horse', hash256), true);
    assert.equal(verify('correct horse', hash512), true);
    assert.equal(verify('correct horse', plain256), true);
  });

  it('rejects a wrong password', function () {
    assert.equal(verify('correct hors', hash256), false);
    assert.equal(verify('', hash512), false);
  });

  it('verifies the specification vectors', function () {
    for (const [, password, expected] of [...vectors256, ...vectors512]) {
      assert.equal(verify(password, expected), true);
      assert.equal(verify(password + 'x', expected), false);
    }
  });

  it('returns false rather than throwing for a password that could never match', function () {
    assert.equal(verify('a'.repeat(1000), hash256), false);
    assert.equal(verify('correct\0horse', hash256), false);
  });

  it('throws for a non-string password or hash', function () {
    assert.throws(() => verify(123, hash256), TypeError);
    assert.throws(() => verify('correct horse', 123), TypeError);
  });

  it('throws for a malformed hash', function () {
    for (const bad of ['', 'plain', '$1$salt$hash', '$5$salt', '$5$salt$short', hash256 + 'x', hash256.replace('$5$', '$6$'), '$5$rounds=x$salt$' + 'a'.repeat(43)]) {
      assert.throws(() => verify('correct horse', bad), TypeError, JSON.stringify(bad));
    }
  });

  it('cannot be tricked by a hash whose rounds field could be read as a salt', function () {
    // JavaScript and C must agree on which field is which, or maxRounds is bypassed.
    // With strict left-to-right parsing this string has a rounds field and a salt but no hash.
    const noSalt = '$5$rounds=10000$' + 'a'.repeat(43);
    assert.throws(() => verify('pw', noSalt, { maxRounds: 5000 }), TypeError);
    // The same with an empty salt is well formed, and maxRounds applies before any hashing
    const emptySalt = '$5$rounds=10000$$' + 'a'.repeat(43);
    assert.throws(() => verify('pw', emptySalt, { maxRounds: 5000 }), RangeError);
    assert.equal(verify('pw', emptySalt), false);
    assert.throws(() => verify('pw', '$5$rounds=-1$salt$' + 'a'.repeat(43)), TypeError);
    assert.throws(() => verify('pw', '$5$rounds=-1$' + 'a'.repeat(43)), TypeError);
    assert.throws(() => verify('pw', '$5$rounds=1000x$' + 'a'.repeat(43)), TypeError);
  });

  it('honours maxRounds', function () {
    assert.equal(verify('correct horse', hash256, { maxRounds: 1000 }), true);
    assert.throws(() => verify('correct horse', hash256, { maxRounds: 999 }), RangeError);
    assert.throws(() => verify('correct horse', sha256crypt('x', '$5$rounds=2000$salt'), { maxRounds: 1000 }), RangeError);
    assert.throws(() => verify('correct horse', plain256, { maxRounds: 4999 }), RangeError);
    assert.throws(() => verify('correct horse', hash256, { maxRounds: 'lots' }), TypeError);
  });

  it('verifyAsync behaves the same', async function () {
    assert.equal(await verifyAsync('correct horse', hash512), true);
    assert.equal(await verifyAsync('wrong', hash512), false);
    assert.equal(await verifyAsync('a'.repeat(1000), hash512), false);
    await assert.rejects(verifyAsync('correct horse', 'junk'), TypeError);
    await assert.rejects(verifyAsync('correct horse', hash512, { maxRounds: 999 }), RangeError);
  });
});

describe('constants', function () {
  it('are exposed and frozen', function () {
    assert.deepEqual(constants, { ROUNDS_DEFAULT: 5000, ROUNDS_MIN: 1000, ROUNDS_MAX: 999999999, SALT_LENGTH_MAX: 16, PASSWORD_MAX_BYTES: 511 });
    assert.ok(Object.isFrozen(constants));
  });
});
