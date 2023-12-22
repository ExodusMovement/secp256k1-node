let BigIntSupportChecked = false;
let secp256k1;

if (!BigIntSupportChecked)
  try {
    BigInt(1);
    const noble_secp256k1 = require("@bitcoinerlab/secp256k1");
    secp256k1 = {
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
      publicKeyTweakAdd: function (
        publicKey,
        tweak,
        compressed = true,
        output
      ) {
        return noble_secp256k1.pointAddScalar(publicKey, tweak, compressed);
      },
      privateKeyNegate: function (seckey) {
        return noble_secp256k1.privateNegate(seckey);
      },
      privateKeyVerify: function (privateKey) {
        return noble_secp256k1.isPrivate(privateKey);
      },
      privateKeyTweakAdd: function (privateKey, tweak) {
        return noble_secp256k1.privateAdd(privateKey, tweak);
      },
      ecdsaVerify: function (sig, msg32, pubkey) {
        return noble_secp256k1.verify(msg32, pubkey, sig);
      },
      ecdsaSign: function (msg32, seckey, options = {}, output) {
        return { signature: secp256k1.sign(msg32, seckey) };
      },
    };
  } catch (e) {
  } finally {
    BigIntSupportChecked = true;
  }

module.exports = secp256k1 || require("./lib")(require("./lib/elliptic"));
