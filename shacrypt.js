"use strict";

const shacrypt = require('./build/Release/shacrypt');
const crypto   = require('crypto');
const util     = require('util');

const sha256cryptAsync = util.promisify(shacrypt.sha256cryptasync);
const sha512cryptAsync = util.promisify(shacrypt.sha512cryptasync);

const isString = (obj) => {
	return Object.prototype.toString.call(obj) === '[object String]';
};

const isNumber = (obj) => {
	return Object.prototype.toString.call(obj) === '[object Number]';
};

function validate(prefix, password, salt, rounds) {

	const _rounds = rounds || 5000;
	let _salt = salt;

	if (!isString(password)) {
		throw new Error('password must be a String');
	}

	if (!isString(salt)) {
		_salt = crypto.randomBytes(16).toString('hex');

		if (isNumber(salt)) {
			_salt = `${prefix}rounds=${salt}$${_salt}`;
		}
	}

	if (isNumber(_rounds) && _salt.indexOf(prefix) === -1) {
		_salt = `${prefix}rounds=${_rounds}$${_salt}`;
	}

	return _salt;
}

/**
 * Generate SHA256-CRYPT hash
 *
 * @param  {String} password
 * @param  {String} [salt]
 * @param  {Number} [rounds]
 * @param  {Function} [callback]
 * @return {String}
 */
exports.sha256crypt = function(password, salt, rounds, callback) {

	salt = validate('$5$', password, salt, rounds);

        if (typeof callback === "function") {
          shacrypt.sha256cryptasync(password, salt, callback);
        } else {
          return shacrypt.sha256crypt(password, salt);
        }
};

/**
 * Generate SHA512-CRYPT hash
 *
 * @param  {String} password
 * @param  {String} [salt]
 * @param  {Number} [rounds]
 * @param  {Function} [callback]
 * @return {String}
 */
exports.sha512crypt = function(password, salt, rounds, callback) {

	salt = validate('$6$', password, salt, rounds);

        if (typeof callback === "function") {
          shacrypt.sha512cryptasync(password, salt, callback);
        } else {
          return shacrypt.sha512crypt(password, salt);
        }
};

/**
 * Generate SHA256-CRYPT hash (async/await compatible)
 *
 * @param  {String} password
 * @param  {String} [salt]
 * @param  {Number} [rounds]
 * @return {Promise<String>}
 */
exports.sha256cryptAsync = async function(password, salt, rounds) {

	salt = validate('$5$', password, salt, rounds);

	return sha256cryptAsync(password, salt);
};

/**
 * Generate SHA512-CRYPT hash (async/await compatible)
 *
 * @param  {String} password
 * @param  {String} [salt]
 * @param  {Number} [rounds]
 * @return {Promise<String>}
 */
exports.sha512cryptAsync = async function(password, salt, rounds) {

	salt = validate('$6$', password, salt, rounds);

	return sha512cryptAsync(password, salt);
};
