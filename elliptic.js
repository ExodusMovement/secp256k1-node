let BigIntSupportChecked = false;
let secp256k1 = require("./lib/elliptic");

if (!BigIntSupportChecked)
  try {
    BigInt(1);
    const noble_secp256k1 = require("@bitcoinerlab/secp256k1");
    secp256k1 = {
      ...secp256k1,
      privateKeyNegate: function (seckey) {
        return noble_secp256k1.privateNegate(seckey);
      },
      publicKeyCreate: function (privateKey, compressed, output) {
        output = noble_secp256k1.pointFromScalar(privateKey, compressed);
        return output;
      },
      publicKeyVerify: function (publicKey) {
        return noble_secp256k1.isPoint(publicKey);
      },
      publicKeyConvert: function (publicKey, compressed, output) {
        output = noble_secp256k1.isPoint(publicKey, compressed);
        return output;
      },
      privateKeyVerify: function (privateKey) {
        return noble_secp256k1.isPrivate(privateKey);
      },
      privateKeyTweakAdd: function (privateKey, tweak) {
        return noble_secp256k1.privateAdd(privateKey, tweak);
      },
      publicKeyTweakAdd: function (publicKey, tweak, compressed, output) {
        output = noble_secp256k1.pointAddScalar(publicKey, tweak, compressed);
        return output;
      },
      ecdsaVerify: function (sig, msg32, pubkey) {
        return noble_secp256k1.verify(msg32, pubkey, sig);
      },
    };
  } catch (e) {
  } finally {
    BigIntSupportChecked = true;
  }

module.exports = require("./lib")(secp256k1);
