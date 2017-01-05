
import fs from "fs";
import {resolve} from "path";

const EXT = ".pem";

const fileNames = fs.readdirSync(resolve(__dirname, "certs")).filter(f => f.endsWith(EXT));

const certs = {};
const keys = {};
const files = fileNames.map((name) => {
  const data = fs.readFileSync(resolve(__dirname, "certs", name), "utf8");
  name = name.slice(0, -EXT.length);
  const [id, category] = name.split(".");
  if (category === "key") {
    keys[id] = data;
  }
  else if (category === "crt") {
    certs[id] = data;
  }
  else {
    throw new Error(`wtf is ${name}.pem, I dunno how to handle it`);
  }
});

export {certs, keys};
