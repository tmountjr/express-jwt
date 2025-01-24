const { KJUR, KEYUTIL } = require('jsrsasign')
const { readFile } = require('jsrsasign-util')
const path = require('path')

const fromBase64Url = (str) => Buffer.from(str, 'base64url').toString()

const jwtSecret = process.env.JWT_SECRET
const publicKey = KEYUTIL.getKey(readFile(path.join(__dirname, '..', '..', 'certs', 'pubkey.pem')).replace(/[\n\r]+/g, ''))

const validate = function(req, res, next) {
  // Get the token from the Authorization header.
  const token = req.headers['authorization'].replace('Bearer ', '')

  // Alternatively, you can take it from a cookie; here we're looking for one called "jwt".
  // const cookies = req.headers.cookie.split('; ')
  // const token = cookies.find(c => /^jwt=/.test(c)).split('=')[1].trim()

  // Get the token header, payload, and signing algorithm used
  const [ header, payload ] = token.split('.')
  const { alg } = JSON.parse(fromBase64Url(header))

  let validationComponent = null,
      isValid = false

  try {
    if (/^HS/.test(alg)) {
      // HSxxx algorithms use a shared secret.
      validationComponent = jwtSecret
    } else if (/^[REP]S/.test(alg)) {
      // RSxxx, ESxxx, and PSxxx algorithms all use a public key.
      validationComponent = publicKey
    } else {
      // Those are the only options; if another one was specified, throw an error.
      console.log(`Invalid algorithm specified: ${alg}`)
      res.status(501).send('Not Implemented')
    }
  } catch (e) {
    console.log(e)
    res.status(500)
  }

  // Validate the JWT using the jsrsasign library.
  isValid = KJUR.jws.JWS.verifyJWT(token, validationComponent, { alg: [alg] })

  if (isValid) {
    // Only if the signature is valid, decode the payload and add it to the request.
    req.payload = JSON.parse(fromBase64Url(payload))
    next()
  } else {
    // If the signature is invalid, abort the request with a 401.
    res.status(401).send('Unauthorized')
  }
}

module.exports = validate