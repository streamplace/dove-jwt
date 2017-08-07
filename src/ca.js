import fs from "fs";

// So we can override it in test mocks
export const CONFIG = {
  SYSTEM_CA_PATH: "/etc/ssl/certs/ca-certificates.crt"
};
export default function getSystemCA() {
  if (!fs.existsSync(CONFIG.SYSTEM_CA_PATH)) {
    throw new Error(`
      Unable to find system root certificates. Probably this means you're on Mac
      or Windows, which don't work so good with dove-jwt right now, see:

      https://github.com/streamplace/dove-jwt/issues/2

      Possibly also you're on a Linux system but don't have ca-certificates installed?
    `);
  }
  const myCAs = fs.readFileSync(CONFIG.SYSTEM_CA_PATH, "utf8");
  return myCAs;
}
