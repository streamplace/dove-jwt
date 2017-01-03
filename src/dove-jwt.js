
// Why is this KJUR?
var jsrsasign = require("jsrsasign");
var forge = require("node-forge");
var x509 = require("x509");
var fs = require("fs");
var path = require("path");
var debug = require("debug");

const log = debug("dove-jwt");

var ASN1HEX = jsrsasign.ASN1HEX;
var JWS = jsrsasign.jws.JWS;
var KEYUTIL = jsrsasign.KEYUTIL;

function splitca(chain, split) {
  split = typeof split !== 'undefined' ? split : "\n";

  var ca = [];
  if(chain.indexOf("-END CERTIFICATE-") < 0 || chain.indexOf("-BEGIN CERTIFICATE-") < 0){
    throw Error("File does not contain 'BEGIN CERTIFICATE' or 'END CERTIFICATE'");
  }
  chain = chain.split(split);
  var cert = [];
  var _i, _len;
  for (_i = 0, _len = chain.length; _i < _len; _i++) {
    var line = chain[_i];
    if (!(line.length !== 0)) {
      continue;
    }
    cert.push(line);
    if (line.match(/-END CERTIFICATE-/)) {
      ca.push(cert.join(split));
      cert = [];
    }
  }
  return ca;
}

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

function pemToDerArray(pem) {
  return splitca(pem).map((pem) => {
    var asn1Cert = forge.pki.certificateFromPem(pem);
    var asn1Obj = forge.pki.certificateToAsn1(asn1Cert);
    var derKey = forge.asn1.toDer(asn1Obj).getBytes();
    return forge.util.encode64(derKey);
  });
}

function derArrayToPem(derArray) {
  return derArray.map((der) => {
    var derKey = forge.util.decode64(der);
    var asnObj = forge.asn1.fromDer(derKey);
    var asn1Cert = forge.pki.certificateFromAsn1(asnObj);
    return forge.pki.certificateToPem(asn1Cert);
  }).join("");
};

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

