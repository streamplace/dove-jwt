
import {splitca, pemToDerArray, derArrayToPem} from "./utils";

// Why is this KJUR?
var jsrsasign = require("jsrsasign");
var forge = require("node-forge");
var fs = require("fs");
var path = require("path");
var debug = require("debug");

const log = debug("dove-jwt");

var ASN1HEX = jsrsasign.ASN1HEX;
var JWS = jsrsasign.jws.JWS;
var KEYUTIL = jsrsasign.KEYUTIL;

var caStore = forge.pki.createCaStore();
const myCAs = fs.readFileSync("/etc/ssl/certs/ca-certificates.crt", "utf8");

let added = 0;
let failed = 0;
splitca(myCAs).forEach(ca => {
  try {
    caStore.addCertificate(ca)
    added += 1;
  }
  catch (e) {
    // This is fine -- forge only supports RSA, so lots of these roots won't work.
    failed += 1;
  }
});
log(`${added} CAs added, ${failed} CAs failed. (This is usually because node-forge only supports RSA.)`);

const keyPem = fs.readFileSync(path.resolve(__dirname, "key.pem"), 'utf8');
const certPem = fs.readFileSync(path.resolve(__dirname, "cert.pem"), 'utf8');
const x5c = pemToDerArray(certPem);
const key = KEYUTIL.getKey(keyPem);

const header = {
  x5c: x5c,
  iss: "drumstick.iame.li",
};
const myJws = JWS.sign("RS256", header, {foo: "bar"}, key);

// const certPEM = fs.readFileSync(path.resolve(__dirname, "cert.pem"), 'utf8');
// Task 1: verify that cert is valid for iss domain
// Task 2: Verify that the thing signs given iss domain

var {headerObj, payloadObj} = JWS.parse(myJws);
const certChain = derArrayToPem(headerObj.x5c);
var pubKey = KEYUTIL.getKey(certChain);
var isValid = JWS.verify(myJws, pubKey, ["RS256"]);

log(isValid ? "valid!" : "invalid!");

try {
  log("before");
  const result = forge.pki.verifyCertificateChain(caStore, splitca(certChain).map(forge.pki.certificateFromPem));
}
catch (e) {
  console.error(e.message);
  throw new Error(e.message);
}
log("after");
// const myJws = KJUR.jws.JWS.sign("RS256", header, {foo: "bar"}, key);

