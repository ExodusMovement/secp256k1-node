const secp256k1 = require('@exodus/bitcoinerlab-secp256k1')

const errors = {
  EXPECTED_PRIVATE: 'Expected Private',
  EXPECTED_POINT: 'Expected Point',
  EXPECTED_SIGNATURE: 'Expected Signature'
}

let elliptic

const verbose = false
function loadLegacy (method, message) {
  if (verbose) {
    if (!message) {
      console.warn(`${method} is not implemented, using legacy approach...`)
    } else console.warn(`${method} | ${message}`)
  }
  if (!elliptic) {
    elliptic = require('./elliptic')
  }
}

function isCompressedPublicKey (array) {
  return array.length === 33
}

module.exports = {
  contextRandomize: function () {
    // Historically served to randomize the context in constant time, RNG is sufficiently randomized internally.
    return 0
  },
  privateKeyVerify: function (privateKey) {
    return secp256k1.isPrivate(privateKey) ? 0 : 1
  },
  privateKeyNegate: function (privateKey) {
    try {
      const res = secp256k1.privateNegate(privateKey)
      if (!res) return 1
      privateKey.set(res)
    } catch (e) {
      loadLegacy('privateKeyNegate', e.toString())
      elliptic.privateKeyNegate(privateKey)
    }
    return 0
  },
  privateKeyTweakAdd: function (privateKey, tweak) {
    try {
      const res = secp256k1.privateAdd(privateKey, tweak)
      if (!res) return 1
      privateKey.set(res)
    } catch (e) {
      return 1
    }
    return 0
  },
  privateKeyTweakMul: function (privateKey, tweak) {
    loadLegacy('privateKeyTweakMul')
    return elliptic.privateKeyTweakMul(privateKey, tweak)
  },
  publicKeyVerify: function (publicKey) {
    return secp256k1.isPoint(publicKey) ? 0 : 1
  },
  publicKeyCreate: function (output, seckey) {
    try {
      const res = secp256k1.pointFromScalar(seckey, isCompressedPublicKey(output))
      if (!res) return 2
      output.set(res)
      return 0
    } catch (e) {
      if (e.toString().includes(errors.EXPECTED_PRIVATE)) return 1
      return 2
    }
  },
  publicKeyConvert: function (output, pubkey) {
    try {
      output.set(secp256k1.pointCompress(pubkey, isCompressedPublicKey(output)))
      return 0
    } catch (e) {
      if (e.toString().includes(errors.EXPECTED_POINT)) return 1
      return 2
    }
  },
  publicKeyNegate: function (output, pubkey) {
    loadLegacy('publicKeyNegate')
    return elliptic.publicKeyNegate(output, pubkey)
  },
  publicKeyCombine: function (output, pubkeys) {
    loadLegacy('publicKeyCombine')
    return elliptic.publicKeyCombine(output, pubkeys)
  },
  publicKeyTweakAdd: function (output, pubkey, tweak) {
    try {
      const res = secp256k1.pointAddScalar(pubkey, tweak, isCompressedPublicKey(output))
      if (!res) return 2
      output.set(res)
      return 0
    } catch (e) {
      if (e.toString().includes(errors.EXPECTED_POINT)) return 1
      return 2
    }
  },
  publicKeyTweakMul: function (output, pubkey, tweak) {
    try {
      const res = secp256k1.pointMultiply(pubkey, tweak, isCompressedPublicKey(output))
      if (!res) return 2
      output.set(res)
      return 0
    } catch (e) {
      if (e.toString().includes(errors.EXPECTED_POINT)) return 1
      return 2
    }
  },
  signatureNormalize: function (sig) {
    loadLegacy('signatureNormalize')
    return elliptic.signatureNormalize(sig)
  },
  signatureExport: function (obj, sig) {
    loadLegacy('signatureExport')
    return elliptic.signatureExport(obj, sig)
  },
  signatureImport: function (output, sig) {
    loadLegacy('signatureImport')
    return elliptic.signatureImport(output, sig)
  },
  ecdsaSign: function (obj, msg32, seckey, data, noncefn) {
    if (noncefn) {
      loadLegacy('ecdsaSign', 'fallback to legacy')
      return elliptic.ecdsaSign(obj, msg32, seckey, data, noncefn)
    }
    try {
      obj.signature.set(secp256k1.sign(msg32, seckey, data))
      Object.defineProperty(obj, 'recid', {
        get: function () {
          loadLegacy('ecdsaSign', 'fallback to legacy')
          const obj = { signature: this.signature, recid: null }
          elliptic.ecdsaSign(obj, msg32, seckey, data, noncefn)
          return obj.recid
        }
      })
      return 0
    } catch (e) {
      if (e.toString().includes(errors.EXPECTED_PRIVATE)) return 1
      return 2
    }
  },
  ecdsaVerify: function (signature, message, publicKey) {
    try {
      return secp256k1.verify(message, publicKey, signature) ? 0 : 3
    } catch (e) {
      if (e.toString().includes(errors.EXPECTED_SIGNATURE)) return 1
      return 2
    }
  },
  ecdsaRecover: function (output, sig, recid, msg32) {
    loadLegacy('ecdsaRecover')
    return elliptic.ecdsaRecover(output, sig, recid, msg32)
  },
  ecdh: function (output, pubkey, seckey, data, hashfn, xbuf, ybuf) {
    loadLegacy('ecdh')
    return elliptic.ecdh(output, pubkey, seckey, data, hashfn, xbuf, ybuf)
  }
}
