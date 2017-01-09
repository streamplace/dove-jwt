
import {pemToDerArray, derArrayToPem} from "../src/utils";
import {certs, keys} from "./certs";
import {DoveJwt} from "../src/dove-jwt";
import jwt from "jsonwebtoken";

const failure = function() {
  return Promise.reject("fail!");
}

const reversePromise = function(prom) {
  return new Promise((resolve, reject) => {
    prom.then(reject).catch(resolve);
  });
};

describe("this test framework", function() {
  it("should have working promise helpers", function() {
    return reversePromise(failure());
  });
});

describe("dove-jwt", function() {
  let dove;

  beforeEach(function() {
    dove = new DoveJwt();
  });

  it("should import some system certs", function() {
    dove.useSystemCertAuthorities();
    const certs = dove.caStore.listAllCertificates();
    expect(certs.length > 1).toBe(true);
  });

  describe("sign", function() {
    it("should handle basic signing", function() {
      const token = dove.sign({foo: "bar"}, keys.example_com, certs.example_com, {domain: "example.com"});
      const decoded = jwt.decode(token, {complete: true});
      expect(decoded).toBeTruthy();
      expect(decoded.payload.foo).toBe("bar");
      expect(decoded.header.x5c).toEqual(pemToDerArray(certs.example_com));
      expect(decoded.header.alg).toBe("RS256");
    });

    xit("should determine the domain from the common name if not provided", function() {

    });

    xit("should fail if issuer header and cert and domain parameter don't match", function() {

    });
  });

  describe("verify", function() {
    it("should handle basic verification", function() {
      dove.addCertAuthority(certs.Fake_Root_Certificate_Authority);
      const token = dove.sign({foo: "bar"}, keys.example_com, certs.example_com, {domain: "example.com"});
      const parsed = dove.verify(token);
      expect(parsed).toBeTruthy();
      expect(parsed.foo).toBe("bar");
    });

    xit("should fail if algorithim isn't RS256", function() {

    });

    xit("should fail if the x5c header is missing", function() {

    });

    xit("should fail if the x5c header is malformed", function() {

    });

    xit("should fail if the x5c header is missing", function() {

    });

    xit("should fail if the issuer isn't formatted properly", function() {

    });

    xit("should fail if the cert doesn't match the issuer", function() {

    });

    xit("should fail if the cert is untrusted", function() {

    });

    xit("should fail if the x5c header is missing", function() {

    });

    // and then just a bunch of standard but important jwt ones i guess.
  });
});
