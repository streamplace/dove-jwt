
import forge from "node-forge";
import debug from "debug";
import fs from "fs";
import jwt from "jsonwebtoken";
import {splitca, pemToDerArray, derArrayToPem} from "./utils";

const log = debug("sk:dove-jwt");

const throwCode = function(code, message) {
  var err = new Error(message);
  err.code = code;
  throw err;
};

export class DoveJwt {
  /**
   * Create a new DoveJwt instance. Usually you won't need to do this -- we've already created one
   * for you that you can get at `import dove from "dove-jwt".` But if you need to have different
   * instances of dove that trust different root CAs, you might make more than one.
   * @return {DoveJwt}
   */
  constructor() {
    this.caStore = forge.pki.createCaStore();
  }

  /**
   * Add one or more trusted root CAs.
   *
   * The behavior here is kinda weird. We only support RSA keys, but we also want to be able to
   * seamlessly import /etc/ssl/certs/ca-certificates.crt. So, if you try and pass in a single PEM
   * file which we can't parse, that's an error. But if you pass in a big ol' bundle of
   * concatenated CAs, we only throw an error if they're all invalid. (And we print a warning, but
   * that'll have to change if people actually lose this library for anything 😀)
   *
   * @param {String} rootCA PEM-encoded root CA. Lots of them concatted together is fine too.
   */
  addCertAuthority(rootCA) {
    let added = 0;
    let failed = 0;
    let lastError;
    splitca(rootCA).forEach(ca => {
      try {
        this.caStore.addCertificate(ca);
        added += 1;
      }
      catch (e) {
        // We can safely ignore this very specific error... I guess. Eew for matching this error
        // this way.
        if (e.message !== "Cannot read public key. OID is not RSA.") {
          throw e;
        }
        else {
          failed += 1;
        }
      }
    });
    if (added === 0 && failed === 0) {
      throw new Error("addCertAuthority called with no keys.");
    }
    if (added === 0) {
      throw new Error("None of the keys passed to addCertAuthority were RSA keys, none added.");
    }
    if (failed > 0) {
      log(`${added} RSA CAs added, ${failed} non-RSA CAs ignored. (This is normal because we only support RSA certs, and is not ordinarily cause for concern)`);
    }
  }

  /**
   * Use the system's built-in root CAs. This is kind of what we had in mind writing dove-jwt, but
   * it's disabled by default b/c self-signed is good too.
   */
  useSystemCertAuthorities() {
    // if your life is worse because this is is sync, let me know and I'll change it! -Eli
    const myCAs = fs.readFileSync(DoveJwt.SYSTEM_CA_PATH, "utf8");
    return this.addCertAuthority(myCAs);
  }

  /**
   * Create a new dove-jwt.
   * @param  {Object} payload   Body of the JWT you'd like to produce. Passed directly to jsonwebtoken.
   * @param  {String} secretKey RSA secret key.
   * @param  {String} cert      RSA cert, signed by your relevant CA.
   * @param  {Object} options   Options object, passed through to [the same configuration options
   *                            of node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken#usage).
   * @return {String} The dove-jwt.
   */
  sign(payload, secretKey, cert, options = {}) {
    const {domain} = options;
    delete options.domain;
    if (!domain || !secretKey || !cert || !domain) {
      throw new Error("Missing required parameters to dove.sign.");
    }
    options.algorithm = "RS256";
    options.issuer = `https://${domain}/`;
    if (!options.header) {
      options.header = {};
    }
    options.header.x5c = pemToDerArray(cert);
    return jwt.sign(payload, secretKey, options);
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
    const {header} = jwt.decode(token, {complete: true});
    const cert = derArrayToPem(header.x5c);
    const payload = jwt.verify(token, cert, {algorithms: "RS256"});
    return payload;
  }
}

// Mostly so it can be overridden in test mocks
DoveJwt.SYSTEM_CA_PATH = "/etc/ssl/certs/ca-certificates.crt";

export default new DoveJwt();
