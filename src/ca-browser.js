import scrapedDebianCAs from "raw-loader!./ca-certificates-browser.crt";

console.warn(`
  Hi there! You're using dove-jwt in a browser. For now, that means that we're
  using a hardcoded list of CAs scraped from Debian. Sorry about that. There
  might be more secure ways to go about it. As always, dove-jwts should be used
  with grains of salt.
`);

export default function getSystemCA() {
  return scrapedDebianCAs;
}
