const AWS = require('aws-sdk');
const async = require('async');
const encoder = require('./encoder');

function decrypt(key, done) {
  var params = {
    CiphertextBlob: encoder.decode(key)
  };

  return new AWS.KMS().decrypt(params, done);
}

function split(stashes, decryptedKeys, done) {
  var result = stashes.map((stash, index) => {
    stash.keyPlaintext = new Buffer(32);
    stash.hmacPlaintext = new Buffer(32);
    decryptedKeys[index].Plaintext.copy(stash.keyPlaintext, 0, 0, 32);
    decryptedKeys[index].Plaintext.copy(stash.hmacPlaintext, 0, 32);
    return stash;
  });
  return done(null, result);
}

function generate(kmsKey, done) {
  const params = {
    KeyId: kmsKey,
    NumberOfBytes: 64
  };

  return new AWS.KMS().generateDataKey(params, done);
}

function stashIt(dataKey, done) {
  const stash = {
    keyPlaintext: new Buffer(32),
    hmacPlaintext: new Buffer(32),
    wrappedKey: encoder.encode(dataKey.CiphertextBlob)
  };

  dataKey.Plaintext.copy(stash.keyPlaintext, 0, 0, 32);
  dataKey.Plaintext.copy(stash.hmacPlaintext, 0, 32);

  return done(null, stash);
}

module.exports = {
  decrypt: (stashes, done) => {
    return async.waterfall([
      async.apply(async.map, stashes.map(s => s.key), decrypt),
      async.apply(split, stashes)
    ], done);
  },

  generate: (kmsKey, done) => {
    return async.waterfall([
      async.apply(generate, kmsKey),
      async.apply(stashIt)
    ], done);
  }
};
