const { KJUR, KEYUTIL } = require('jsrsasign')

const fromBase64Url = (str) => Buffer.from(str, 'base64url').toString()

const validate = function(req, res, next) {
  const { token, ...other } = req.body
  const [ header, payload ] = token.split('.')
  const { alg } = JSON.parse(fromBase64Url(header))

  let validationComponent = null,
      isValid = false

  try {
    if (/^HS/.test(alg)) {
      validationComponent = process.env.JWT_SECRET
    } else if (/^[REP]S/.test(alg)) {
      validationComponent = KEYUTIL.getKey(other.pubKey)
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