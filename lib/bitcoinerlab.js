const secp256k1 = require('@exodus/bitcoinerlab-secp256k1')
let elliptic

function loadLegacy (method, message) {
  if (!message) {
    console.warn(`${method} is not implemented, using legacy approach...`)
  } else console.warn(`${method} | ${message}`)
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
      return { output: secp256k1.pointFromScalar(privateKey, compressed), res: 0 }
    } catch (e) {
      return { res: 1 }
    }
  },
  publicKeyConvert: function (publicKey, compressed) {
    try {
      return { output: secp256k1.pointCompress(publicKey, compressed), res: 0 }
    } catch (e) {
      return { res: 1 }
    }
  },
  publicKeyNegate: function (publicKey, compressed, output) {
    throw new Error('publicKeyNegate is not implemented')
  },
  publicKeyCombine: function (publicKeys, compressed, output) {
    throw new Error('publicKeyCombine is not implemented')
  },
  publicKeyTweakAdd: function (publicKey, tweak, compressed = true, output) {
    if (output) {
      throw new Error('publicKeyTweakAdd | output param not handled')
    }
    return secp256k1.pointAddScalar(publicKey, tweak, compressed)
  },
  publicKeyTweakMul: function (publicKey, tweak, compressed, output) {
    if (output) {
      throw new Error('publicKeyTweakMul | output param not handled')
    }
    return secp256k1.pointMultiply(publicKey, tweak, compressed)
  },
  signatureNormalize: function (signature) {
    throw new Error('signatureNormalize is not implemented')
  },
  signatureExport: function (signature, output) {
    throw new Error('signatureExport is not implemented')
  },
  signatureImport: function (signature, output) {
    throw new Error('signatureImport is not implemented')
  },
  ecdsaSign: function (message, privateKey, options = {}, output) {
    if (output) {
      throw new Error('ecdsaSign | output param not handled')
    }
    return {
      signature: secp256k1.sign(message, privateKey),
      get recid () {
        throw new Error('ecdsaSign | recoverable signing is not implemented')
      }
    }
  },
  ecdsaVerify: function (signature, message, publicKey) {
    return secp256k1.verify(message, publicKey, signature)
  },
  ecdsaRecover: function (signature, recid, compressed, output) {
    throw new Error('ecdsaRecover is not implemented')
  },
  ecdh: function (publicKey, privateKey, opts) {
    throw new Error('ecdh is not implemented')
  }
}
