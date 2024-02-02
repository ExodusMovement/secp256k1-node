let secp256k1

try {
  secp256k1 = require('./noble')
} catch (e) {
  secp256k1 = require('./elliptic')
}

module.exports = secp256k1
