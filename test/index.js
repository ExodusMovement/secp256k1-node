const test = require('tape')
const util = require('./util')

function testAPI (secp256k1, description) {
  test(description, (t) => {
    util.setSeed(util.env.seed)

    require('./context')(t, secp256k1)
    require('./privatekey')(t, secp256k1)
    require('./publickey')(t, secp256k1)
    require('./signature')(t, secp256k1)
    require('./ecdsa')(t, secp256k1)
    require('./ecdh')(t, secp256k1)

    t.end()
  })
}

testAPI(require('../elliptic'), 'elliptic')
testAPI(require('../bitcoinerlab'), 'bitcoinerlab')
