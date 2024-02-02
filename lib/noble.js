// Pre-load elliptic as a backup
const elliptic = require('./elliptic')
const necc = require('@noble/secp256k1')
const hmac = require('@noble/hashes/hmac')
const sha256 = require('@noble/hashes/sha256')

function _interopNamespaceDefault (e) {
  const n = Object.create(null)
  if (e) {
    Object.keys(e).forEach(function (k) {
      if (k !== 'default') {
        const d = Object.getOwnPropertyDescriptor(e, k)
        Object.defineProperty(n, k, d.get ? d : {
          enumerable: true,
          get: function () { return e[k] }
        })
      }
    })
  }
  n.default = e
  return Object.freeze(n)
}

const noble = _interopNamespaceDefault(necc)

noble.utils.hmacSha256Sync = (key, ...msgs) =>
  hmac.hmac(sha256.sha256, key, noble.utils.concatBytes(...msgs))
noble.utils.sha256Sync = (...msgs) => sha256.sha256(noble.utils.concatBytes(...msgs))

function isCompressedPublicKey (array) {
  return array.length === 33
}

function hexToNumber (hex) {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToNumber: expected string, got ' + typeof hex)
  }
  return BigInt(`0x${hex}`)
}

function normalizeScalar (scalar) {
  let num
  if (typeof scalar === 'bigint') {
    num = scalar
  } else if (
    typeof scalar === 'number' &&
    Number.isSafeInteger(scalar) &&
    scalar >= 0
  ) {
    num = BigInt(scalar)
  } else if (typeof scalar === 'string') {
    if (scalar.length !== 64) { throw new Error('Expected 32 bytes of private scalar') }
    num = hexToNumber(scalar)
  } else if (scalar instanceof Uint8Array) {
    if (scalar.length !== 32) { throw new Error('Expected 32 bytes of private scalar') }
    num = hexToNumber(noble.utils.bytesToHex(scalar))
  } else {
    throw new TypeError('Expected valid private scalar')
  }
  if (num < 0) throw new Error('Expected private scalar >= 0')
  return num
}

function _isPoint (p) {
  try {
    return !!noble.Point.fromHex(p)
  } catch (e) {
    return false
  }
}

function _isSignature (sig) {
  const sigObj = { r: sig.slice(0, 32), s: sig.slice(32, 64) }
  const sigr = hexToNumber(noble.utils.bytesToHex(sigObj.r))
  const sigs = hexToNumber(noble.utils.bytesToHex(sigObj.s))
  if (sigr >= noble.CURVE.n || sigs >= noble.CURVE.n) return false
  return true
}

module.exports = {
  ...elliptic,
  publicKeyVerify: function (publicKey) {
    return _isPoint(publicKey) ? 0 : 1
  },
  publicKeyCreate: function (output, seckey) {
    try {
      output.set(noble.getPublicKey(seckey, isCompressedPublicKey(output)))
    } catch (e) {
      console.error('publicKeyCreate failed', e)
      return 1
    }
    return 0
  },
  publicKeyConvert: function (output, pubkey) {
    try {
      output.set(
        noble.Point.fromHex(pubkey).toRawBytes(isCompressedPublicKey(output))
      )
    } catch (e) {
      console.error('publicKeyConvert failed', e)
      return 1
    }
    return 0
  },
  publicKeyTweakAdd: function (output, pubkey, tweak) {
    try {
      const P = noble.Point.fromHex(pubkey)
      const t = normalizeScalar(tweak)
      const Q = noble.Point.BASE.multiplyAndAddUnsafe(P, t, BigInt(1))
      if (!Q) return 2
      output.set(Q.toRawBytes(isCompressedPublicKey(output)))
    } catch (e) {
      console.error('publicKeyTweakAdd failed', e)
      if (e.message.includes('Point.fromHex: received invalid point.')) return 1
      return 2
    }
    return 0
  },
  ecdsaSign: function (obj, msg32, seckey, data, noncefn) {
    if (noncefn) {
      return elliptic.ecdsaSign(obj, msg32, seckey, data, noncefn)
    }
    try {
      const [signature, recoveryId] = noble.signSync(msg32, seckey, { der: false, extraEntropy: data, recovered: true })
      obj.signature.set(signature)
      obj.recid = recoveryId
    } catch (e) {
      console.error('ecdsaSign failed', e)
      return 1
    }
    return 0
  },
  ecdsaRecover: function (output, sig, recid, msg32) {
    if (!_isSignature(sig)) return 1
    try {
      output.set(noble.recoverPublicKey(msg32, sig, recid, isCompressedPublicKey(output)))
    } catch (e) {
      console.error('ecdsaRecover failed', e)
      return 2
    }
    return 0
  },
  ecdsaVerify: function (sig, msg32, pubkey) {
    if (!_isSignature(sig)) return 1
    if (!_isPoint(pubkey)) return 2

    try {
      return noble.verify(sig, msg32, pubkey) ? 0 : 3
    } catch (e) {
      console.error('ecdsaVerify failed', e)
      return 1
    }
  }
}
