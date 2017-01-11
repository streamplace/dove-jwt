dove-jwt
========

[![Build Status](https://travis-ci.org/streamkitchen/dove-jwt.svg?branch=master)](https://travis-ci.org/streamkitchen/dove-jwt)

(That stands for **Do**main **Ve**rified **J**SON **W**eb **T**okens.)

Limitations
-----------

* Currently only can use system certificates on Linux, not Mac or Windows. ([#2](https://github.com/streamkitchen/dove-jwt/issues/2))
* Only works with the common name (CN) record on the cert, not any Subject Alternative Names ([#3](https://github.com/streamkitchen/dove-jwt/issues/3))

Tests
-----

`npm run test`

Currently we're using jasmine-es6 rather than jest because of [a bug in node-forge](https://github.com/digitalbazaar/forge/issues/362).
