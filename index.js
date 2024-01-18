let BigIntSupportChecked = false
let secp256k1

if (!BigIntSupportChecked) {
  try {
    BigInt(1)
    secp256k1 = require('./bitcoinerlab')
  } catch (e) {
    secp256k1 = require('./elliptic')
  } finally {
    BigIntSupportChecked = true
  }
}

module.exports = secp256k1
