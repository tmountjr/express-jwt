const { KJUR, KEYUTIL } = require('jsrsasign')
const { readFile } = require('jsrsasign-util')
const path = require('path')

const fromBase64Url = (str) => Buffer.from(str, 'base64url').toString()

const jwtSecret = process.env.JWT_SECRET
const publicKey = KEYUTIL.getKey(readFile(path.join(__dirname, '..', '..', 'certs', 'pubkey.pem')).replace(/[\n\r]+/g, ''))

const validate = function(req, res, next) {
  const token = req.headers['authorization'].replace('Bearer ', '')
  const [ header, payload ] = token.split('.')
  const { alg } = JSON.parse(fromBase64Url(header))

  let validationComponent = null,
      isValid = false

  try {
    if (/^HS/.test(alg)) {
      validationComponent = jwtSecret
    } else if (/^[REP]S/.test(alg)) {
      validationComponent = publicKey
    } else {
      console.log(`Invalid algorithm specified: ${alg}`)
      res.status(501).send('Not Implemented')
    }
  } catch (e) {
    console.log(e)
    res.status(500)
  }

  isValid = KJUR.jws.JWS.verifyJWT(token, validationComponent, { alg: [alg] })

  if (isValid) {
    req.payload = JSON.parse(fromBase64Url(payload))
    next()
  } else {
    res.status(401).send('Unauthorized')
  }
}

module.exports = validate