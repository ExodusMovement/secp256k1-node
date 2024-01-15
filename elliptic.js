let BigIntSupportChecked = false;
let secp256k1;

if (!BigIntSupportChecked)
  try {
    BigInt(1);
    secp256k1 = require("./lib/bitcoinerlab")
  } catch (e) {
    secp256k1 = require("./lib/elliptic")
  } finally {
    BigIntSupportChecked = true;
  }

module.exports = require("./lib")(secp256k1);
