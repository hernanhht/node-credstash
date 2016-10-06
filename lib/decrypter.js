const aesjs = require('aes-js');
const encoder = require('./encoder');

module.exports = {
  decrypt: (stashes, done) => {
    const decrypted = stashes.map(stash => {
      const key = stash.keyPlaintext;
      const value = encoder.decode(stash.contents);
      const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(1));
      const decryptedBytes = aesCtr.decrypt(value);
      return decryptedBytes.toString();
    });

    return done(null, decrypted);
  },

  encrypt: (value, stash, done) => {
    const key = stash.keyPlaintext;

    const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(1));
    const encryptedBytes = aesCtr.encrypt(value);

    stash.contents = encoder.encode(encryptedBytes);

    return done(null, stash);
  }
};
