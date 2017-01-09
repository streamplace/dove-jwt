
import {splitca, pemToDerArray, derArrayToPem} from "../src/utils";
import {certs, keys} from "./certs.js";

describe("splitca", function(){
  it("should split PEM files", function() {
    const cert1 = certs.example_com;
    const cert2 = certs.wrongdomain_example_pizza;
    const combined = cert1 + cert2 + cert1 + cert2 + cert1;
    const split = splitca(combined);
    // Strip the trailing newline from these
    expect(split).toEqual([cert1, cert2, cert1, cert2, cert1].map(c => c.trim()));
  });
});

describe("conversion functions", function() {
  it("should handle PEM to DER array and back", function() {
    Object.keys(certs).forEach((certName) => {
      const cert = certs[certName];
      const derArray = pemToDerArray(cert);
      expect(derArray.length).toEqual(1);
      const back = derArrayToPem(derArray);
      expect(back).toEqual(cert);
    });
  });
});
