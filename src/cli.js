import dove from "./dove-jwt";
import yargs from "yargs";
import winston from "winston";
import fs from "fs";

const argv = yargs
  .option("ca-file", {
    description: "file containing your trusted cert authorities",
    type: "string"
  })
  .option("cert-file", {
    description: "file containing your public TLS cert",
    type: "string"
  })
  .option("key-file", {
    description: "file containing your private key for the relevant domain",
    type: "string"
  })
  .command(
    "message",
    "create a dove-jwt containing a string message",
    yargs => {
      yargs.demand("cert-file");
      yargs.demand("key-file");
      yargs.demand(1);
    },
    argv => {
      const message = argv._[1];
      if (!argv.caFile) {
        dove.useSystemCertAuthorities();
      } else {
        const cas = fs.readFileSync(argv.caFile, "utf8");
        dove.addCertAuthority(cas);
      }
      const cert = fs.readFileSync(argv.certFile, "utf8");
      const key = fs.readFileSync(argv.keyFile, "utf8");
      const signed = dove.sign({ message }, key, cert);
      process.stdout.write(signed);
    }
  )
  .help().argv;
