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

function hexToNumber(hex) {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
  }
  return BigInt(`0x${hex}`);
}

function normalizeScalar(scalar) {
  let num;
  if (typeof scalar === 'bigint') {
    num = scalar;
  } else if (
    typeof scalar === 'number' &&
    Number.isSafeInteger(scalar) &&
    scalar >= 0
  ) {
    num = BigInt(scalar);
  } else if (typeof scalar === 'string') {
    if (scalar.length !== 64)
      throw new Error('Expected 32 bytes of private scalar');
    num = hexToNumber(scalar);
  } else if (scalar instanceof Uint8Array) {
    if (scalar.length !== 32)
      throw new Error('Expected 32 bytes of private scalar');
    num = hexToNumber(noble.utils.bytesToHex(scalar));
  } else {
    throw new TypeError('Expected valid private scalar');
  }
  if (num < 0) throw new Error('Expected private scalar >= 0');
  return num;
}

module.exports = {
  contextRandomize: function () {
    // Historically served to randomize the context in constant time, RNG is sufficiently randomized internally.
    return 0
  },
  privateKeyVerify: function (seckey) {
    // tiny-secp256k1 is 2x faster than elliptic, still not noticeable irl
    return elliptic.privateKeyVerify(seckey)
  },
  privateKeyNegate: function (seckey) {
    return elliptic.privateKeyNegate(seckey)
  },
  privateKeyTweakAdd: function (seckey, tweak) {
    return elliptic.privateKeyTweakAdd(seckey, tweak)
  },
  privateKeyTweakMul: function (seckey, tweak) {
    return elliptic.privateKeyTweakMul(seckey, tweak)
  },
  publicKeyVerify: function (publicKey) {
    try{
      noble.Point.fromHex(publicKey);
      return 0
    }catch(e){}
    return 1
  },
  publicKeyCreate: function (output, seckey) {
    try {
      output.set(noble.getPublicKey(seckey, isCompressedPublicKey(output)))
      return 0
    } catch (e) {
      console.error('publicKeyCreate failed', e)
      return 1
    }
  },
  publicKeyConvert: function (output, pubkey) {
    try {
      output.set(
        bitcoinerlab.pointCompress(pubkey, isCompressedPublicKey(output))
      )
      return 0
    } catch (e) {
      console.error('publicKeyConvert failed', e)
      if (e.message === errors.EXPECTED_POINT) return 1
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
      const P = noble.Point.fromHex(pubkey);
      const t = normalizeScalar(tweak);
      const Q = noble.Point.BASE.multiplyAndAddUnsafe(P, t, BigInt(1));
      if (!Q) throw new Error('Tweaked point at infinity');
      output.set(Q.toRawBytes(isCompressedPublicKey(output)))


      // const res = bitcoinerlab.pointAddScalar(
      //   pubkey,
      //   tweak,
      //   isCompressedPublicKey(output)
      // )
      // if (!res) return 2
      // output.set(res)
      // return 0
    } catch (e) {
      console.error('publicKeyTweakAdd failed', e)
      if (e.message === errors.EXPECTED_POINT) return 1
      return 2
    }
    return 0
  },
  publicKeyTweakMul: function (output, pubkey, tweak) {
    try {
      const res = bitcoinerlab.pointMultiply(
        pubkey,
        tweak,
        isCompressedPublicKey(output)
      )
      if (!res) return 2
      output.set(res)
      return 0
    } catch (e) {
      console.error('publicKeyTweakMul failed', e)
      if (e.message === errors.EXPECTED_POINT) return 1
      return 2
    }
  },
  signatureNormalize: function (sig) {
    try {
      sig.set(
        noble.Signature.fromCompact(sig).normalizeS().toCompactRawBytes()
      )
    } catch (e) {
      console.error('signatureNormalize failed', e)
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
      const { signature, recoveryId } = bitcoinerlab.signRecoverable(msg32, seckey, data)
      obj.signature.set(signature)
      obj.recid = recoveryId
    } catch (e) {
      console.error('ecdsaSign failed', e)
      return 1
    }
    return 0
  },
  ecdsaVerify: function (signature, message, publicKey) {
    try {
      return bitcoinerlab.verify(message, publicKey, signature) ? 0 : 3
    } catch (e) {
      console.error('ecdsaVerify failed', e)
      if (e.message === errors.EXPECTED_SIGNATURE) return 1
      return 2
    }
  },
  ecdsaRecover: function (output, sig, recid, msg32) {
    const sigObj = { r: sig.slice(0, 32), s: sig.slice(32, 64) }
    const sigr = hexToNumber(noble.utils.bytesToHex(sigObj.r))
    const sigs = hexToNumber(noble.utils.bytesToHex(sigObj.s))
    if (sigr >= noble.CURVE.n || sigs >= noble.CURVE.n) return 1

    try {
      const res = bitcoinerlab.recover(
        msg32,
        sig,
        recid,
        isCompressedPublicKey(output)
      )
      if (!res) return 1
      output.set(res)
    } catch (e) {
      console.error('ecdsaRecover failed', e)
      return 2
    }
    return 0
  },
  ecdh: function (output, pubkey, seckey, data, hashfn, xbuf, ybuf) {
    return elliptic.ecdh(output, pubkey, seckey, data, hashfn, xbuf, ybuf)
  }
}
