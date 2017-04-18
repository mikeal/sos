let sos = require('./')()
let assert = require('assert')

let encoded = sos.encode({test: true})
let decoded = sos.decode(encoded)

assert.deepEqual(decoded, {test: true})

encoded = sos.encode(new Buffer('asdf'))
decoded = sos.decode(encoded)

assert.deepEqual(decoded, new Buffer('asdf'))
