const async = require('async');
const decrypter = require('./lib/decrypter');
const encoder = require('./lib/encoder');
const hmac = require('./lib/hmac');
const keys = require('./lib/keys');
const secrets = require('./lib/secrets');
const xtend = require('xtend');

const defaults = {
  limit: 1
};

function Credstash(config) {
  this.table = config ? config.table : undefined;
  this.kms_key = config ? config.kms.key : 'alias/credstash';
}

Credstash.prototype.get = function(name, options, done) {
  if (typeof options === 'function') {
    done = options;
    options = defaults;
  } else {
    options = xtend(defaults, options);
  }

  return async.waterfall([
    async.apply(secrets.get, this.table, name, options),
    async.apply(keys.decrypt),
    async.apply(hmac.check),
    async.apply(decrypter.decrypt)
  ], function (err, secrets) {
    if (err) {
      return done(err);
    }

    if (options.limit === 1) {
      return done(null, secrets && secrets[0]);
    }

    done(null, secrets);
  });
};

Credstash.prototype.put = function(name, value, version, options, done) {
  if (typeof version === 'function') {
    done = version;
    version = null;
    options = defaults;
  }

  if (typeof options === 'function') {
    done = options;
    options = defaults;
  } else {
    options = xtend(defaults, options);
  }

  return async.waterfall([
    async.apply(keys.generate, this.kms_key),
    async.apply(decrypter.encrypt, value),
    async.apply(hmac.sign),
    async.apply(secrets.put, this.table, name, version)
  ], function (err, secrets) {
    if (err) {
      return done(err);
    }

    done(null, secrets);
  });
};

module.exports = Credstash;
