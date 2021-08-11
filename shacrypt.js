"use strict";

const shacrypt = require('./build/Release/shacrypt');
const crypto   = require('crypto');

const isString = function(obj) {
	return Object.prototype.toString.call(obj) == '[object String]';
};

const isNumber = function(obj) {
	return Object.prototype.toString.call(obj) == '[object Number]';
};

function validate (prefix, password, salt, rounds) {
	let _salt = salt;
	const _rounds = rounds || 5000;

	if (!isString(password)) {
		throw new Error('password must be a String');
	}

	if (!isString(salt)) {
		_salt = crypto.randomBytes(16).toString('hex');

		if (isNumber(salt)) {
			_salt = prefix + 'rounds=' + salt + '$' + _salt;
		}
	}

	if (isNumber(_rounds) && _salt.indexOf(prefix) == -1) {
		_salt = prefix + 'rounds=' + _rounds + '$' + _salt;
	}

	return _salt;
}

function timingSafeEqual (a, b, encoding = 'utf8') {
	const x = Buffer.from(a, encoding);
	const y = Buffer.from(b, encoding);

	if (x.length !== y.length) {
		return false;
	}

	return crypto.timingSafeEqual(x, y);
}

function extract (hashString) {
	const segments = hashString.split('$');
	const prefix = segments[1];
	let rounds = segments[2];
	let salt = segments[3];
	let hash = segments[4];

	if (typeof salt !== 'string') {
		throw new Error('Unexpected salt value');
	}

	if (typeof rounds === 'string' && /^rounds=\d+$/.test(rounds)) {
		rounds = parseInt(rounds.split('=').pop());

		if (isNaN(rounds)) {
			rounds = null;
		}
	} else {
		hash = salt;
		salt = rounds;
		rounds = null;
	}

	return {
		prefix: prefix,
		rounds: rounds,
		salt: salt,
		hash: hash
	};
}

/**
 * Generate SHA256-CRYPT hash
 *
 * @param  {String} password
 * @param  {String} [salt]
 * @param  {Number} [rounds]
 * @return {String}
 */
function sha256crypt (password, salt, rounds) {
	salt = validate('$5$', password, salt, rounds);
	return shacrypt.sha256crypt(password, salt);
};

/**
 * Generate SHA256-CRYPT hash async
 *
 * @param  {String} password
 * @param  {String} [salt]
 * @param  {Number} [rounds]
 * @param  {Function} [callback]
 * @return {undefined | Promise<string>}
 */
function sha256cryptAsync (password, salt, rounds, callback) {
	salt = validate('$5$', password, salt, rounds);

	if (typeof callback === "function") {
		shacrypt.sha256cryptasync(password, salt, callback);
		return;
	}

	return new Promise(function(resolve, reject) {
		shacrypt.sha256cryptasync(password, salt, function(err, res) {
			if (err) {
				reject(err);
				return;
			}

			resolve(res);
		});
	});
};

/**
 * Generate SHA512-CRYPT hash
 *
 * @param  {String} password
 * @param  {String} [salt]
 * @param  {Number} [rounds]
 * @return {String}
 */
function sha512crypt (password, salt, rounds) {
	salt = validate('$6$', password, salt, rounds);
	return shacrypt.sha512crypt(password, salt);
};

/**
 * Generate SHA512-CRYPT hash async
 *
 * @param  {String} password
 * @param  {String} [salt]
 * @param  {Number} [rounds]
 * @param  {Function} [callback]
 * @return {undefined | Promise<string>}
 */
function sha512cryptAsync (password, salt, rounds, callback) {
	salt = validate('$6$', password, salt, rounds);

	if (typeof callback === "function") {
		shacrypt.sha512cryptasync(password, salt, callback);
		return;
	}

	return new Promise(function(resolve, reject) {
		shacrypt.sha512cryptasync(password, salt, function(err, res) {
			if (err) {
				reject(err);
				return;
			}

			resolve(res);
		});
	});
};

/**
 * Verify hash against password
 *
 * @param  {String} password
 * @param  {String} [storedHash]
 * @return {Promise<boolean>}
 */
async function verify (password, storedHash) {
	const storedHashParts = extract(storedHash);

	let cryptMethod;

	switch (storedHashParts.prefix) {
		case '6':
			cryptMethod = sha512cryptAsync;
			break;
		case '5':
			cryptMethod = sha256cryptAsync;
			break;
		default:
			throw new Error('Unknown prefix');
	}

	const hash = await cryptMethod(password, storedHashParts.salt, storedHashParts.rounds);
	const hashParts = extract(hash);

	return timingSafeEqual(hashParts.hash, storedHashParts.hash);
}

exports.sha256crypt = sha256crypt;
exports.sha256cryptAsync = sha256cryptAsync;
exports.sha512crypt = sha512crypt;
exports.sha512cryptAsync = sha512cryptAsync;
exports.verify = verify;
