// Pre-load elliptic as a backup
const elliptic = require('./elliptic')
const bitcoinerlab = require('@exodus/bitcoinerlab-secp256k1')
const noble = require('@noble/secp256k1')

const errors = {
  EXPECTED_PRIVATE: 'Expected Private',
  EXPECTED_POINT: 'Expected Point',
  EXPECTED_SIGNATURE: 'Expected Signature'
}

function isCompressedPublicKey (array) {
  return array.length === 33
}


function bigEndianArray(number, byteLength = 32) {
  const buffer = Buffer.alloc(byteLength);
  
  let n = BigInt(number);
  
  for (let i = byteLength - 1; i >= 0; i--) {
    buffer[i] = Number(n & BigInt(0xff));
    n >>= BigInt(8);
  }
  
  return Array.from(buffer);
}

module.exports = {
  contextRandomize: function () {
    // Historically served to randomize the context in constant time, RNG is sufficiently randomized internally.
    return 0
  },
  privateKeyVerify: function (privateKey) {
    return bitcoinerlab.isPrivate(privateKey) ? 0 : 1
  },
  privateKeyNegate: function (privateKey) {
    try {
      const res = bitcoinerlab.privateNegate(privateKey)
      if (!res) return 1
      privateKey.set(res)
    } catch (e) {
      elliptic.privateKeyNegate(privateKey)
    }
    return 0
  },
  privateKeyTweakAdd: function (privateKey, tweak) {
    try {
      const res = bitcoinerlab.privateAdd(privateKey, tweak)
      if (!res) return 1
      privateKey.set(res)
    } catch (e) {
      return 1
    }
    return 0
  },
  privateKeyTweakMul: function (seckey, tweak) {
    try{
      const keyNum = noble.utils._normalizePrivateKey(seckey)
      const tweakNum = noble.utils._normalizePrivateKey(tweak)
      seckey.set(bigEndianArray(noble.utils.mod(keyNum * tweakNum, noble.CURVE.n)))
    }catch(e){
      return 1
    }
    return 0
  },
  publicKeyVerify: function (publicKey) {
    return bitcoinerlab.isPoint(publicKey) ? 0 : 1
  },
  publicKeyCreate: function (output, seckey) {
    try {
      const res = bitcoinerlab.pointFromScalar(seckey, isCompressedPublicKey(output))
      if (!res) return 2
      output.set(res)
      return 0
    } catch (e) {
      return 1
    }
  },
  publicKeyConvert: function (output, pubkey) {
    try {
      output.set(bitcoinerlab.pointCompress(pubkey, isCompressedPublicKey(output)))
      return 0
    } catch (e) {
      if (e.message === errors.EXPECTED_POINT) return 1
      return 2
    }
  },
  publicKeyNegate: function (output, pubkey) {
    try {
      output.set(noble.Point.fromHex(pubkey).negate().toRawBytes(isCompressedPublicKey(output)))
    } catch (e) {
      return 1
    }
    return 0
  },
  publicKeyCombine: function (output, pubkeys) {
    try {
      let point = noble.Point.fromHex(pubkeys[0])
      for (let i = 1; i < pubkeys.length; ++i) {
        point = point.add(noble.Point.fromHex(pubkeys[i]))
      }
      try {
        point.assertValidity()
      } catch (err) {
        return 2
      }
      output.set(point.toRawBytes(isCompressedPublicKey(output)))
    } catch (e) {
      return 1
    }
    return 0
  },
  publicKeyTweakAdd: function (output, pubkey, tweak) {
    try {
      const res = bitcoinerlab.pointAddScalar(pubkey, tweak, isCompressedPublicKey(output))
      if (!res) return 2
      output.set(res)
      return 0
    } catch (e) {
      if (e.message === errors.EXPECTED_POINT) return 1
      return 2
    }
  },
  publicKeyTweakMul: function (output, pubkey, tweak) {
    try {
      const res = bitcoinerlab.pointMultiply(pubkey, tweak, isCompressedPublicKey(output))
      if (!res) return 2
      output.set(res)
      return 0
    } catch (e) {
      if (e.message === errors.EXPECTED_POINT) return 1
      return 2
    }
  },
  signatureNormalize: function (sig) {
    try{
      sig.set(noble.Signature.fromCompact(sig).normalizeS().toCompactRawBytes())
    }catch(e){
      return 1
    }
    return 0
  },
  signatureExport: function (obj, sig) {
    return elliptic.signatureExport(obj, sig)
  },
  signatureImport: function (output, sig) {
    return elliptic.signatureImport(output, sig)
  },
  ecdsaSign: function (obj, msg32, seckey, data, noncefn) {
    if (noncefn) {
      return elliptic.ecdsaSign(obj, msg32, seckey, data, noncefn)
    }
    try {
      obj.signature.set(bitcoinerlab.sign(msg32, seckey, data))
      Object.defineProperty(obj, 'recid', {
        get: function () {
          const obj = { signature: this.signature, recid: null }
          elliptic.ecdsaSign(obj, msg32, seckey, data, noncefn)
          return obj.recid
        }
      })
      return 0
    } catch (e) {
      if (e.message === errors.EXPECTED_PRIVATE) return 1
      return 2
    }
  },
  ecdsaVerify: function (signature, message, publicKey) {
    try {
      return bitcoinerlab.verify(message, publicKey, signature) ? 0 : 3
    } catch (e) {
      if (e.message === errors.EXPECTED_SIGNATURE) return 1
      return 2
    }
  },
  ecdsaRecover: function (output, sig, recid, msg32) {
    return elliptic.ecdsaRecover(output, sig, recid, msg32)
  },
  ecdh: function (output, pubkey, seckey, data, hashfn, xbuf, ybuf) {
    return elliptic.ecdh(output, pubkey, seckey, data, hashfn, xbuf, ybuf)
  }
}
