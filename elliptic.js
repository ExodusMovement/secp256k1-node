const defaultLib = require('./lib')(require('./lib/elliptic'))
const secp = require('@bitcoinerlab/secp256k1')
module.exports = {
    ...defaultLib,
    publicKeyCreate (seckey, compressed = true) {
        return secp.pointFromScalar(seckey, compressed)
    },
    privateKeyVerify (seckey) {
        return secp.isPrivate(seckey)
    },
    publicKeyVerify (seckey) {
        return secp.isPoint(seckey)
    },
    publicKeyConvert (seckey, compressed) {
        return secp.pointCompress(seckey, compressed)
    },
    privateKeyTweakAdd (seckey, tweak) {
        return secp.privateAdd(seckey, tweak)
    },
    publicKeyTweakAdd (seckey, tweak, compress) {
        return secp.pointAddScalar(seckey, tweak, compress)
    },
    ecdsaSign (hash, privateKey, options = {}) {
        return secp.sign(hash, privateKey, options.data)
    },
    ecdsaVerify (sign, hash, publicKey) {
        return secp.verify(hash, publicKey, sign)
    },
}
