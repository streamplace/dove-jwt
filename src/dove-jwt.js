
export class DoveJwt {
  /**
   * Create a new DoveJwt instance. Usually you won't need to do this -- we've already created one
   * for you that you can get at `import dove from "dove-jwt".` But if you need to have different
   * instances of dove that trust different root CAs, you might make more than one.
   * @return {DoveJwt}
   */
  constructor() {
    // set empty trusted CAs
  }

  /**
   * Add one or more trusted root CAs.
   * @param {String} rootCA PEM-encoded root CA. Lots of them concatted together is fine too.
   */
  addCertAuthority(rootCA) {

  }

  /**
   * Use the system's built-in root CAs. This is kind of what we had in mind writing dove-jwt, but
   * it's disabled by default b/c self-signed is good too.
   * @return {[type]} [description]
   */
  useSystemCertAuthorities() {

  }

  /**
   * Create a new dove-jwt.
   * @param  {Object} payload   Body of the JWT you'd like to produce.
   * @param  {String} secretKey RSA secret key.
   * @param  {String} cert      RSA cert, signed by your relevant CA.
   * @param  {Object} options   Options object, passed through to [the same configuration options
   *                            of node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken#usage).
   * @return {String} The dove-jwt.
   */
  sign(payload, secretKey, cert, options) {

  }

  /**
   * Parse and verify a dove-jwt.
   * @param  {[type]} token The dove-jwt
   * @return {Object}       Returns a decrypted JWT. Otherwise, throws an error otherwise. If
   *                        you want to look at the (evil, invalid, not-to-be-trusted) JWT
   *                        after a verification failure, it's available on the `decryptedJwt`
   *                        property of the error.
   */
  verify(token) {

  }
}

export default new DoveJwt();
