const express = require('express')
const path = require('path')
const cors = require('cors')
const bodyParser = require('body-parser')
const validate = require('./middleware/Validate.js')
const injectJwks = require('./middleware/InjectJwks.js')

// JWKS handling
const { JWKS } = require('./JWKS.js')
const store = new JWKS()

/**
 * Initialize the JWKS store with the certificates.
 */
async function initStore() {
  const basepath = path.join(__dirname, '..', 'certs')
  await store.add(`${basepath}/jwks00.privkey.pem`, `${basepath}/jwks00.fullchain.pem`)
  await store.add(`${basepath}/jwks01.privkey.pem`, `${basepath}/jwks01.fullchain.pem`)
  console.log('JWKS loaded.')
}
initStore().catch(err => {
  console.log(err)
})

const app = express()
app.use(express.static(path.join(__dirname, 'public')))
app.use(cors())
app.use(bodyParser.json())

app.post('/api/validate', injectJwks(store), validate, (req, res) => {
  res.json(req.payload)
})

app.get('/.well-known/openid-configuration', (req, res) => {
  const jwks = store.asJWKS()
  res.json(jwks)
})

const port = process.env.PORT || 3000
app.listen(port, () => {
  console.log(`Server running on port ${port}`)
})
