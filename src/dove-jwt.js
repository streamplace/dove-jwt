
// Why is this KJUR?
var jsrsasign = require("jsrsasign");
var fs = require("fs");
var path = require("path");
var forge = require("node-forge");

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


console.log(isValid ? "valid!" : "invalid!");
console.log(payloadObj);
// const myJws = KJUR.jws.JWS.sign("RS256", header, {foo: "bar"}, key);

