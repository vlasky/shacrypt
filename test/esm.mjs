import assert from 'node:assert/strict';
import { sha256crypt, sha512cryptAsync, verify, constants } from '@vlasky/shacrypt';
import * as namespace from '@vlasky/shacrypt';

describe('ES module import', function () {
  it('exposes named exports', function () {
    assert.equal(typeof sha256crypt, 'function');
    assert.equal(typeof sha512cryptAsync, 'function');
    assert.equal(typeof verify, 'function');
    assert.equal(constants.ROUNDS_DEFAULT, 5000);
  });

  it('namespace import matches the named exports', function () {
    assert.equal(namespace.sha256crypt, sha256crypt);
    assert.equal(namespace.verify, verify);
  });
});
