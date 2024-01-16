let BigIntSupportChecked = false
let secp256k1

if (!BigIntSupportChecked) {
  try {
    BigInt(1)
    secp256k1 = require('./lib')(require('./lib/bitcoinerlab'), true)
  } catch (e) {
    secp256k1 = require('./lib')(require('./lib/elliptic'))
  } finally {
    BigIntSupportChecked = true
  }
}

module.exports = secp256k1
