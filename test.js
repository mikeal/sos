let sos = require('./')()
let assert = require('assert')

let encoded = sos.encode({test: true})
let decoded = sos.decode(encoded)

assert.deepEqual(decoded, {test: true})

encoded = sos.encode(new Buffer('asdf'))
decoded = sos.decode(encoded)

assert.deepEqual(decoded, new Buffer('asdf'))

let to = require('./')()

encoded = sos.encrypt(new Buffer('asdf'), to.keypair.publicKey)
assert.ok(to.validate(encoded))
decoded = to.decrypt(encoded)

assert.deepEqual(decoded, new Buffer('asdf'))

encoded = sos.encrypt({test: [1, 2, 3]}, to.keypair.publicKey)
assert.ok(to.validate(encoded))
decoded = to.decrypt(encoded)

assert.deepEqual(decoded, {test: [1, 2, 3]})
