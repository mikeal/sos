const sodi = require('sodi')

const toBuffer = data => {
  let encoding = Object.keys(data)[0]
  if (encoding === 'json') return new Buffer(JSON.stringify(data[encoding]))
  return new Buffer(data[encoding], encoding)
}

class SOS {
  constructor (keypair) {
    this.keypair = keypair || sodi.generate()
    this._sodi = sodi(this.keypair)
    this.authorities = []
  }
  validate (object) {
    let value = toBuffer(object.data)
    let signature = toBuffer(object.signature.data)
    let publicKey = toBuffer(object.from.data)
    // TODO: validate authorities
    return sodi.verify(value, signature, publicKey)
  }
  encode (object) {
    let data
    let value
    if (Buffer.isBuffer(object)) {
      data = { hex: object.toString('hex') }
      value = object
    } else {
      value = JSON.stringify(object)
      data = { json: object }
    }
    let ret = {
      data,
      signature: {
        authorities: this.authorities,
        data: { hex: this._sodi.sign(value).toString('hex') }
      },
      from: {
        data: { hex: this.keypair.publicKey.toString('hex') }
      }
    }
    return ret
  }
  decode (object, validate = true) {
    if (validate) {
      let valid = this.validate(object)
      if (!valid) {
        throw new Error('Validation failed.')
      }
    }
    if (object.data.json) return object.data.json
    else {
      let encoding = Object.keys(object.data)[0]
      return new Buffer(object.data[encoding], encoding)
    }
  }
  identities (object, validate = true) {
    if (validate) {
      let valid = this.validate(object)
      if (!valid) {
        throw new Error('Validation failed.')
      }
    }
    return object.signature.authorities.map(a => a.data.json)
  }
}

module.exports = keypair => new SOS(keypair)



