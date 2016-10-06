const AWS = require('aws-sdk');
const async = require('async');
const https = require('https');
const pad = require('pad');

const PAD_LEN = 19;

const agent = new https.Agent({
  rejectUnauthorized: true,
  keepAlive: true,
  ciphers: 'ALL',
  secureProtocol: 'TLSv1_method'
});

function find(table, name, options, done) {
  var params = {
    TableName: table || 'credential-store',
    ConsistentRead: true,
    Limit: options.limit,
    ScanIndexForward: false,
    KeyConditions: {
      name: {
        ComparisonOperator: 'EQ',
        AttributeValueList: [{
          S: name
        }]
      }
    }
  };

  if (options.projection) {
    params.ProjectionExpression = options.projection;
  }

  return new AWS.DynamoDB({
    httpOptions: { agent: agent }
  }).query(params, done);
}

function map(name, data, done) {
  if (!data.Items || data.Items.length === 0) {
    return done(new Error('secret not found: ' + name));
  }

  var result = data.Items.map(item => ({
    key: item.key.S,
    hmac: item.hmac.S,
    contents: item.contents.S
  }));

  return done(null, result);
}

function put(table, name, stash, version, done) {
  var params = {
    Item: {
      name: name,
      version: version,
      key: stash.wrappedKey, // b64encoded encrypted datakey CiphertextBlob (32->64 bytes of the key)
      contents: stash.contents, // b64encoded value
      hmac: stash.hmac, // b64encoded encrypted datakey CiphertextBlob (0->31 bytes of the key)
      digest: 'SHA256'
    },
    TableName: table || 'credential-store',
    ConditionExpression: 'attribute_not_exists(#name)',
    ExpressionAttributeNames: {
      "#name": "name"
    }
  };

  return new AWS.DynamoDB.DocumentClient({
    httpOptions: { agent: agent }
  }).put(params, done);
}

function getVersion(table, name, version, done) {
  if (version) {
    return done(null, version);
  }

  find(table, name, {projection: 'version'}, done);
}

function padVersion(version, done) {
  if (typeof version === 'object' && Array.isArray(version.Items) && version.Items.length > 0 ) {
    version = Number(version.Items.shift().version.S);
    version++;
  } else {
    version = 1;
  }

  return done(null, pad(PAD_LEN, version, '0'));
}

module.exports = {
  get: (table, name, options, done) => {
    return async.waterfall([
      async.apply(find, table, name, options),
      async.apply(map, name),
    ], done);
  },

  put: (table, name, version, stash, done) => {
    return async.waterfall([
      async.apply(getVersion, table, name, version),
      async.apply(padVersion),
      async.apply(put, table, name, stash)
    ], done);
  }
};
