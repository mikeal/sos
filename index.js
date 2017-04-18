const sodi = require('sodi')

const toBuffer = data => {
  let encoding
  if (data.hex) encoding = 'hex'
  else if (data.base64) encoding = 'base64'
  else if (data.json) return new Buffer(JSON.stringify(data.json))
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
    else return toBuffer(object.data)
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
  encrypt (object, to) {
    let data = {}
    if (!Buffer.isBuffer(object)) {
      data.contentType = 'application/json'
      object = new Buffer(JSON.stringify(object))
    }
    let encrypted = this._sodi.encrypt(object, to)
    data.hex = encrypted.box.toString('hex')
    data.nonce = encrypted.nonce
    let ret = {
      data,
      signature: {
        authorities: this.authorities,
        data: { hex: this._sodi.sign(encrypted.box).toString('hex') }
      },
      from: {
        data: { hex: this.keypair.publicKey.toString('hex') }
      }
    }
    return ret
  }
  decrypt (object, validate = true) {
    if (validate) {
      let valid = this.validate(object)
      if (!valid) {
        throw new Error('Validation failed.')
      }
    }
    // Verify this is to my public key.
    // It just fails now on decryption when it is for the wrong key.
    let box = toBuffer(object.data)
    let decrypted = this._sodi.decrypt(box, object.data.nonce, toBuffer(object.from.data))
    if (object.data.contentType === 'application/json') {
      return JSON.parse(decrypted.toString())
    }
    return decrypted
  }
}

module.exports = keypair => new SOS(keypair)
