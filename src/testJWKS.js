const { JWKS } = require("./JWKS.js");

(async () => {

  const store = new JWKS()
  // Add the private key and the fullchain certificate.
  const addedKey = await store.add('../certs/jwks01.privkey.pem', '../certs/jwks01.fullchain.pem')
  const legacyKey = await store.add('../certs/jwks00.privkey.pem', '../certs/jwks00.fullchain.pem')

  // Create a JWKS representation and dump it to the console.
  const jwks = store.asJWKS()
  console.log(JSON.stringify(jwks, null, 2))
  console.log('\n*****\n')

  // Using the key ID, retrieve the public key and dump it to the console.
  const { kid } = addedKey
  const legacyKid = legacyKey.kid
  const publickey = store.publicKeyAsPem(kid)
  console.log(publickey)
  console.log('\n*****\n')

  if (store.canSign) {
    const payload = {
      sub: '1234567890',
      name: 'John Doe',
      iat: Math.floor(Date.now() / 1000)
    }
    const jwt = await store.sign(payload, kid)
    const legacyJwt = await store.sign(payload, legacyKid)
    console.log(jwt)
    console.log('\n*****\n')
    console.log(legacyJwt)
    console.log('\n*****\n')
  } else {
    console.log('Cannot sign with a public key only. Please add a private key.')
  }

  process.exit()

})()
