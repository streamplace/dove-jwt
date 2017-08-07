import forge from "node-forge";
import debug from "debug";
import jwt from "jsonwebtoken";
import { splitca, pemToDerArray, derArrayToPem } from "./utils";
import { parse as urlParse } from "url";
import getSystemCAs from "./ca.js";

const log = debug("sk:dove-jwt");

const throwCode = function(code) {
  const err = new Error(code);
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
      } catch (e) {
        // We can safely ignore this very specific error... I guess. Eew for matching this error
        // this way.
        if (e.message !== "Cannot read public key. OID is not RSA.") {
          throw e;
        } else {
          failed += 1;
        }
      }
    });
    if (added === 0 && failed === 0) {
      throw new Error("addCertAuthority called with no keys.");
    }
    if (added === 0) {
      throw new Error(
        "None of the keys passed to addCertAuthority were RSA keys, none added."
      );
    }
    if (failed > 0) {
      log(
        `${added} RSA CAs added, ${failed} non-RSA CAs ignored. (This is normal because we only support RSA certs, and is not ordinarily cause for concern)`
      );
    }
  }

  /**
   * Use the system's built-in root CAs as best as we can. See ca.js for details but basically only
   * works on Debian-y systems right now. See ca.js and ca-browser.js.
   */
  useSystemCertAuthorities() {
    const systemCAs = getSystemCAs();
    this.addCertAuthority(systemCAs);
  }

  /**
   * Throws a cert_untrusted error if the cert isn't trusted according to our CA store.
   * @param  {Strong} cert PEM formatted cert
   */
  verifyCertTrusted(cert) {
    try {
      const result = forge.pki.verifyCertificateChain(
        this.caStore,
        splitca(cert).map(forge.pki.certificateFromPem)
      );
    } catch (e) {
      log("Error from forge.pki.verifyCertificateChain", e);
      throwCode("cert_untrusted");
    }
  }

  /**
   * If we weren't provided an issuer, derive it from the cert
   * @param  {String} cert PEM-formatted certificate
   * @return {String} https://example.com/
   */
  getIssuer(cert) {
    const forgeCert = forge.pki.certificateFromPem(cert);
    const subject = forgeCert.subject.getField("CN");
    const commonName = subject.value;
    return `https://${commonName}/`;
  }

  verifyCertIssuerMatch(cert, issuer) {
    if (!issuer) {
      throwCode("issuer_missing");
    }
    const { host } = urlParse(issuer);
    if (issuer !== `https://${host}/`) {
      log(`Malformed issuer: "${issuer}" should be of form "https://${host}/"`);
      throwCode("issuer_invalid");
    }
    let commonName;
    try {
      const forgeCert = forge.pki.certificateFromPem(cert);
      const subject = forgeCert.subject.getField("CN");
      commonName = subject.value;
    } catch (e) {
      log("Error from forge", e);
      throwCode("x5c_invalid");
    }
    if (host !== commonName) {
      log(`Incorrect issuer: ${host} !== ${commonName}`);
      throwCode("issuer_wrong");
    }
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
    if (!payload || !secretKey || !cert) {
      throw new Error("Missing required parameters to dove.sign.");
    }
    this.verifyCertTrusted(cert);
    options.algorithm = "RS256";
    if (!options.issuer) {
      options.issuer = this.getIssuer(cert);
    } else {
      this.verifyCertIssuerMatch(cert, options.issuer);
    }
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
    const { header, payload: untrustedPayload } = jwt.decode(token, {
      complete: true
    });
    if (!header.x5c) {
      throwCode("x5c_missing");
    }
    let cert;
    try {
      cert = derArrayToPem(header.x5c);
    } catch (e) {
      log("Error from forge", e);
      throwCode("x5c_invalid");
    }
    this.verifyCertTrusted(cert);
    this.verifyCertIssuerMatch(cert, untrustedPayload.iss);
    // jsonwebtoken checks for this, but it's v important, so let's check too
    if (header.alg !== "RS256") {
      throwCode("algorithm_invalid");
    }
    const trustedPayload = jwt.verify(token, cert, { algorithms: "RS256" });
    return trustedPayload;
  }
}

const defaultDove = new DoveJwt();
export default defaultDove;
