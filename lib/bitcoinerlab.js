const secp256k1 = require('@exodus/bitcoinerlab-secp256k1')

const verbose = false
function loadLegacy(method, message) {
  if (verbose) {
    if (!message) {
      console.warn(`${method} is not implemented, using legacy approach...`)
    } else console.warn(`${method} | ${message}`)
  }
  if (!ellipticLib) {
    ellipticLib = require('./elliptic')
  }
}

let ellipticLib
const elliptic = new Proxy(Object.create(null), {
  get(target, key) {
    loadLegacy(key)
    return ellipticLib[key]
  },
})

function compressed(array) {
  return array.length === 33
}

module.exports = {
  contextRandomize: function () {
    return 0
  },
  privateKeyVerify: function (privateKey) {
    return secp256k1.isPrivate(privateKey) ? 0 : 1
  },
  privateKeyNegate: function (privateKey) {
    try {
      privateKey.set(secp256k1.privateNegate(privateKey))
    } catch (e) {
      loadLegacy('privateKeyNegate', e.toString())
      elliptic.privateKeyNegate(privateKey)
    }
    return 0
  },
  privateKeyTweakAdd: function (privateKey, tweak) {
    try {
      privateKey.set(secp256k1.privateAdd(privateKey, tweak))
    } catch (e) {
      return 1
    }
    return 0
  },
  privateKeyTweakMul: function (privateKey, tweak) {
    return elliptic.privateKeyTweakMul(privateKey, tweak)
  },
  publicKeyVerify: function (publicKey) {
    return secp256k1.isPoint(publicKey) ? 0 : 1
  },
  publicKeyCreate: function (output, seckey) {
    try {
      output.set(secp256k1.pointFromScalar(seckey, compressed(output)))
      return 0
    } catch (e) {
      if (e.toString().includes('Expected Private')) return 1
      return 2
    }
  },
  publicKeyConvert: function (output, pubkey) {
    try {
      output.set(secp256k1.pointCompress(pubkey, compressed(output)))
      return 0
    } catch (e) {
      if (e.toString().includes('Expected Point')) return 1
      return 2
    }
  },
  publicKeyNegate: function (output, pubkey) {
    return elliptic.publicKeyNegate(output, pubkey)
  },
  publicKeyCombine: function (output, pubkeys) {
    return elliptic.publicKeyCombine(output, pubkeys)
  },
  publicKeyTweakAdd: function (output, pubkey, tweak) {
    try {
      output.set(secp256k1.pointAddScalar(pubkey, tweak, compressed(output)))
      return 0
    } catch (e) {
      if (e.toString().includes('Expected Point')) return 1
      return 2
    }
  },
  publicKeyTweakMul: function (output, pubkey, tweak) {
    try {
      output.set(secp256k1.pointMultiply(pubkey, tweak, compressed(output)))
      return 0
    } catch (e) {
      if (e.toString().includes('Expected Point')) return 1
      return 2
    }
  },
  signatureNormalize: function (sig) {
    return elliptic.signatureNormalize(sig)
  },
  signatureExport: function (obj, sig) {
    return elliptic.signatureExport(obj, sig)
  },
  signatureImport: function (output, sig) {
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
        },
      })
      return 0
    } catch (e) {
      if (e.toString().includes('Expected Private')) return 1
      return 2
    }
  },
  ecdsaVerify: function (signature, message, publicKey) {
    try {
      return secp256k1.verify(message, publicKey, signature) ? 0 : 3
    } catch (e) {
      if (e.toString().includes('Expected Signature')) return 1
      return 2
    }
  },
  ecdsaRecover: function (output, sig, recid, msg32) {
    return elliptic.ecdsaRecover(output, sig, recid, msg32)
  },
  ecdh: function (output, pubkey, seckey, data, hashfn, xbuf, ybuf) {
    return elliptic.ecdh(output, pubkey, seckey, data, hashfn, xbuf, ybuf)
  },
}
