/**
 * Inject the JWKS store into the request.
 * @param {any} store The JWKS store.
 * @returns The next middleware in the chain.
 */
const injectJwks = (store) => {
  return function (req, res, next) {
    res.locals.store = store
    next()
  }
}

module.exports = injectJwks