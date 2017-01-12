# dove-jwt

[![Build Status](https://travis-ci.org/streamkitchen/dove-jwt.svg?branch=master)](https://travis-ci.org/streamkitchen/dove-jwt)

(That stands for **Do**main **Ve**rified **J**SON **W**eb **T**okens.)

## What is?

[JWTs](https://jwt.io/) are good. One of the ways JWTs may be signed and verified are with an RSA public/private keypair.

With dove-jwt, we take this to its logical conclusion and use your TLS key as the private key, and your CA-verified TLS certificate chain as the public key. The following things are true of a valid `dove-jwt`:

* The JWT is signed using the RS265 algorithm.
* [The x5c header](https://tools.ietf.org/html/rfc7515#section-4.1.6) contains a CA-verified certificate chain.
* The first certificate in this chain validates as the correct public key for the JWT.
* [The iss (issuer) claim](https://tools.ietf.org/html/rfc7519#section-4.1.1) matches the Common Name [CN] on the signing certificate.

Thus, through the magic of the global X.509 key infrastructure, you can be reasonably confident that posession of a valid dove-jwt indicates that it really was signed by the issuer specified in the `iss` header.

## How use?

**Signing:**

```javascript
import dove from "dove-jwt";
import fs from "fs";

const cert = fs.readFileSync("example-com-cert.pem", "utf8");
const key = fs.readFileSync

# Unless you're doing something with self-signed CAs, you'll want to use the system certs.
dove.useSystemCertAuthorities();

// The "options" field is passed through to jsonwebtoken.
const token = dove.sign({foo: "bar", key, cert, {/* options */});

export default token;
```

**Verifying:**

```javascript
import dove from "dove-jwt";
import token from "./signing.js";

dove.useSystemCertAuthorities();

const parsed = dove.verify(token); // will throw an error unless valid
console.log(parsed.foo) // bar
```

## Current Limitations

* Only works with RSA, not ECC keys. This is a limitation of node-forge.
* Currently only can use system certificates on Linux, not Mac or Windows. ([#2](https://github.com/streamkitchen/dove-jwt/issues/2))
* Only works with the common name (CN) record on the cert, not any Subject Alternative Names ([#3](https://github.com/streamkitchen/dove-jwt/issues/3))
* Only supports `RS256` encryption algorithm. We could probably support the other `RS` algorithms without much trouble, just have to test it.

Tests
-----

`npm run test`

Currently we're using jasmine-es6 rather than jest because of [a bug in node-forge](https://github.com/digitalbazaar/forge/issues/362).
