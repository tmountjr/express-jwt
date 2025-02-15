const jose = require('node-jose')
const crypto = require('node:crypto')
const fs = require('node:fs/promises')

class JWKS {
  /** The underlying keystore. */
  #store = jose.JWK.createKeyStore()

  /** Whether or not this store can sign tokens. */
  #canSign = false

  constructor() {
    //
  }

  /**
   * Indicates whether the store is capable of signing a payload.
   * @returns {boolean} True if the store can sign, false otherwise.
   */
  get canSign() {
    return this.#canSign
  }

  /**
   * Add a certificate and chain to the store.
   * @param {string} pathToKey The path to the key in PEM format. Can be a public or private key, but only private keys can sign requests.
   * @param {string} pathToCertChain The path to the certificate chain in PEM format.
   * @returns {Promise<jose.JWK.key>}
   */
  async add(pathToKey, pathToCertChain) {
    const key = await fs.readFile(pathToKey)
    const chain = await fs.readFile(pathToCertChain)

    const keyAsText = key.toString()
    const chainAsText = chain.toString()

    // If we're uploading a private key, or we already have, allow this instance to sign payloads.
    this.#canSign = this.#canSign || keyAsText.startsWith('-----BEGIN PRIVATE KEY-----')

    // Parse the chain for the required x5c values.
    const begin = '-----BEGIN CERTIFICATE-----'
    const end = '-----END CERTIFICATE-----'
    const certsPem = chainAsText.split(end)
      .map(cert => cert.trim())
      .filter(cert => cert)
      .map(cert => `${cert}${end}`)

    const certsDer = certsPem.map(certPem =>
      certPem.replace(begin, '')
        .replace(end, '')
        .replace(/[\n\r]/gm, '')
    )
    const thumbprints = certsDer.map(certDer => {
      let sha1 = crypto.createHash('sha1')
      sha1.update(certDer)
      return sha1.digest('base64')
    })

    return this.#store.add(key, 'pem', {
      use: 'sig',
      alg: 'RS256',
      x5c: certsDer,
      x5t: thumbprints[0]
    })
  }

  /**
   * Remove a key from the store by its ID.
   * @param {string} kid The Key ID to remove.
   */
  remove(kid) {
    const toRemove = this.#store.get(kid)
    if (toRemove) this.#store.remove(toRemove)
    // TODO: if we removed our only remaining private key, then we need to change #canSign.
  }

  /**
   * Sign a JWT.
   * @param {any} payload The payload to sign.
   * @param {string} kid The Key ID to use for signing. If not provided, the first key in the store will be used.
   * @returns {Promise<jose.JWS.createSignResult>} The signed JWT.
   */
  async sign(payload, kid = null) {
    // If we haven't added a private key to the store, don't allow signing.
    if (!this.#canSign) {
      throw new Error('Unable to sign messages with only a public key.')
    }

    // The iss field isn't required but is a good idea.
    if (!('iss' in payload)) {
      payload.iss = 'ExampleJWKS'
    }

    let signer
    if (kid) {
      signer = jose.JWS.createSign({ format: 'compact'}, this.#store.get(kid))
    } else {
      signer = jose.JWS.createSign({ format: 'compact'}, this.#store.get())
    }
    signer.update(JSON.stringify(payload))
    return signer.final()
  }

  /**
   * The JWKS object suitable for pasting into a JWKS endpoint.
   * @param {boolean} includePrivate Include private key information in the JWKS. NOT RECOMMENDED.
   * @returns {any}
   */
  asJWKS(includePrivate = false) {
    return this.#store.toJSON(includePrivate)
  }

  /**
   * Get the PEM-formatted public key for a given Key ID.
   * @param {string} kid The Key ID to retrieve.
   * @returns {string}
   */
  publicKeyAsPem(kid) {
    const key = this.#store.get(kid)
    if (!key) {
      throw new Error(`Key with ID ${kid} not found.`)
    }
    return key.toPEM(false)
  }
}

module.exports = {
  JWKS
}