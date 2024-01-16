const secp256k1 = require('@exodus/bitcoinerlab-secp256k1')
let elliptic

const verbose = true
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
    loadLegacy('privateKeyTweakMul')
    return elliptic.privateKeyTweakMul(privateKey, tweak)
  },
  publicKeyVerify: function (publicKey) {
    return secp256k1.isPoint(publicKey) ? 0 : 1
  },
  publicKeyCreate: function (privateKey, compressed) {
    try {
      return {
        output: Buffer.from(secp256k1.pointFromScalar(privateKey, compressed)),
        res: 0
      }
    } catch (e) {
      if (e.toString().includes('Expected Private')) return { res: 1 }
      return { res: 2 }
    }
  },
  publicKeyConvert: function (publicKey, compressed) {
    try {
      return {
        output: Buffer.from(secp256k1.pointCompress(publicKey, compressed)),
        res: 0
      }
    } catch (e) {
      if (e.toString().includes('Expected Point')) return { res: 1 }
      return { res: 2 }
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
  publicKeyTweakAdd: function (publicKey, tweak, compressed) {
    try {
      return {
        output: Buffer.from(
          secp256k1.pointAddScalar(publicKey, tweak, compressed)
        ),
        res: 0
      }
    } catch (e) {
      if (e.toString().includes('Expected Point')) return { res: 1 }
      return { res: 2 }
    }
  },
  publicKeyTweakMul: function (publicKey, tweak, compressed) {
    try {
      return {
        output: Buffer.from(
          secp256k1.pointMultiply(publicKey, tweak, compressed)
        ),
        res: 0
      }
    } catch (e) {
      if (e.toString().includes('Expected Point')) return { res: 1 }
      return { res: 2 }
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
  ecdsaSign: function (message, privateKey, options) {
    try {
      return {
        res: 0,
        output: {
          signature: Buffer.from(secp256k1.sign(message, privateKey, options.data)),
          recid: 0
        }
      }
    } catch (e) {
      if (e.toString().includes('Expected Private')) { return { res: 1 } }
      return { res: 2 }
    }
  },
  ecdsaVerify: function (signature, message, publicKey) {
    // TODO: errors
    return secp256k1.verify(message, publicKey, signature) ? 0 : 3
  },
  ecdsaRecover: function (output, sig, recid, msg32) {
    loadLegacy('ecdsaRecover')
    return elliptic.ecdsaRecover(output, sig, recid, msg32)
  },
  ecdh: function (output, pubkey, seckey, data, hashfn, xbuf, ybuf) {
    loadLegacy('ecdsaRecover')
    return elliptic.ecdh(output, pubkey, seckey, data, hashfn, xbuf, ybuf)
  }
}
