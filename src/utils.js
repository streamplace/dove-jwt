
import forge from "node-forge";

/**
 * Split a PEM file containing multiple certs into an array of PEM certs.
 *
 * Adapted from https://github.com/bushong1/split-ca
 * @param  {String} chain
 * @return {String}
 */
export function splitca(chain) {
  const split = "\n";

  const ca = [];
  if(chain.indexOf("-END CERTIFICATE-") < 0 || chain.indexOf("-BEGIN CERTIFICATE-") < 0){
    throw Error("File does not contain 'BEGIN CERTIFICATE' or 'END CERTIFICATE'");
  }
  chain = chain.split(split);
  let cert = [];
  let _i;
  let _len;
  for (_i = 0, _len = chain.length; _i < _len; _i++) {
    const line = chain[_i];
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

export function pemToDerArray(pem) {
  return splitca(pem).map((pem) => {
    const asn1Cert = forge.pki.certificateFromPem(pem);
    const asn1Obj = forge.pki.certificateToAsn1(asn1Cert);
    const derKey = forge.asn1.toDer(asn1Obj).getBytes();
    return forge.util.encode64(derKey);
  });
}

export function derArrayToPem(derArray) {
  return derArray.map((der) => {
    const derKey = forge.util.decode64(der);
    const asnObj = forge.asn1.fromDer(derKey);
    const asn1Cert = forge.pki.certificateFromAsn1(asnObj);
    // node-forge returns things with \r\n and that breaks our tests, so...
    const pem = forge.pki.certificateToPem(asn1Cert);
    return pem.split("\r\n").join("\n");
  }).join("");
}
