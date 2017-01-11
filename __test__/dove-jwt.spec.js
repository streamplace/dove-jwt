
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
  let otherDove; // so we have two with different CA stores

  beforeEach(function() {
    dove = new DoveJwt();
    dove.addCertAuthority(certs.Fake_Root_Certificate_Authority);
    otherDove = new DoveJwt();
  });

  it("should import some system certs", function() {
    otherDove.useSystemCertAuthorities();
    const certs = otherDove.caStore.listAllCertificates();
    expect(certs.length > 1).toBe(true);
  });

  describe("sign", function() {
    it("should handle basic signing", function() {
      const token = dove.sign({foo: "bar"}, keys.example_com, certs.example_com, {issuer: "https://example.com/"});
      const decoded = jwt.decode(token, {complete: true});
      expect(decoded).toBeTruthy();
      expect(decoded.payload.foo).toBe("bar");
      expect(decoded.header.x5c).toEqual(pemToDerArray(certs.example_com));
      expect(decoded.header.alg).toBe("RS256");
    });

    xit("should determine the domain from the common name if not provided", function() {
      const token = dove.sign({foo: "bar"}, keys.example_com, certs.example_com);
      const decoded = jwt.decode(token, {complete: true});
      console.log(decoded.header);
    });

    it("should fail to sign if the cert is untrusted", function() {
      expect(function() {
        otherDove.sign({foo: "bar"}, keys.example_com, certs.example_com, {domain: "example.com"});
      }).toThrowError("cert_untrusted");
    });

    xit("should fail if cert and domain parameter don't match", function() {
      expect(function() {
        dove.sign({foo: "bar"}, keys.example_com, certs.example_com, {domain: "wrongdomain.example.com"});
      }).toThrowError("domain_mismatch");
      expect(function() {
        dove.sign({foo: "bar"}, keys.wrongdomain_example_pizza, certs.wrongdomain_example_pizza, {domain: "example.com"});
      }).toThrowError("domain_mismatch");
    });
  });

  describe("verify", function() {
    let exampleToken;
    let options;

    beforeEach(function() {
      options = {
        algorithm: "RS256",
        issuer: `https://example.com/`,
        header: {
          x5c: pemToDerArray(certs.example_com),
        },
      };
      exampleToken = jwt.sign({foo: "bar"}, keys.example_com, options);
    });

    it("should handle basic verification", function() {
      const parsed = dove.verify(exampleToken);
      expect(parsed).toBeTruthy();
      expect(parsed.foo).toBe("bar");
    });

    xit("should fail if algorithim isn't RS256", function() {
      options.algorithm = "HS256";
      const token = jwt.sign({foo: "bar"}, keys.example_com, options);
      expect(function() {
        dove.verify(token);
      }).toThrowError("algorithm_invalid");
    });

    xit("should fail if the x5c header is missing", function() {
      delete options.header.x5c;
      const token = jwt.sign({foo: "bar"}, keys.example_com, options);
      expect(function() {
        dove.verify(token);
      }).toThrowError("x5c_missing");
    });

    xit("should fail if the x5c header is malformed", function() {
      options.header.x5c = ["not", "good", "hex", "data"];
      const token = jwt.sign({foo: "bar"}, keys.example_com, options);
      expect(function() {
        dove.verify(token);
      }).toThrowError("x5c_malformed");
    });

    xit("should fail if the issuer isn't formatted properly", function() {
      ([
        "http://example.com",
        "https://wrongdomain.example.com/this/is/more/path",
      ]).forEach(function(issuer) {
        options.issuer = issuer;
        const token = jwt.sign({foo: "bar"}, keys.example_com, options);
        expect(function() {
          dove.verify(token);
        }).toThrowError("issuer_invalid");
      });
    });

    xit("should fail if the cert doesn't match the issuer", function() {
      ([
        "https://wrongdomain.example.com/",
        "https://otherdomain.example.com/",
        "https://google.com/"
      ]).forEach(function(issuer) {
        options.issuer = issuer;
        const token = jwt.sign({foo: "bar"}, keys.example_com, options);
        expect(function() {
          dove.verify(token);
        }).toThrowError("issuer_wrong");
      });
    });

    it("should fail if the cert is untrusted", function() {
      expect(function() {
        otherDove.verify(exampleToken);
      }).toThrowError("cert_untrusted");
    });
  });
});
